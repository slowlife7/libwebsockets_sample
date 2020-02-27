#include <string.h>
#include <signal.h>
#include <libwebsockets.h>

#define RING_DEPTH 4096

struct msg
{
  void *payload;
  size_t len;
  char binary;
  char first;
  char final;
};

struct per_session_data
{
  struct lws_ring *ring;
  char    ip[32];
  uint32_t fd;
  uint32_t msglen;
  uint32_t tail;
  uint8_t completed : 1;
  uint8_t flow_controlled : 1;
  uint8_t write_consume_pending : 1;
};

struct vhd_handle
{
  struct lws_context *context;
  struct lws_vhost *vhost;

  int *interrupted;
  int *options;
  int *fd;
  const char **ip;
};

static void destroy_msg(void *_msg)
{
  struct msg *msg = _msg;
  free(msg->payload);
  msg->payload = NULL;
  msg->len = 0;
}

static int interrupted, port = 7681, options;
static int fd;
static char ip[32] = "";

static const struct lws_protocol_vhost_options pvo_ip = {
  NULL,
  NULL,
  "ip",
  (void*)&ip
};

static const struct lws_protocol_vhost_options pvo_fd = {
    &pvo_ip,
    NULL,
    "fd",
    (void*)&fd
};
  

static const struct lws_protocol_vhost_options pvo_options = {
      &pvo_fd,
          NULL,
              "options",      
                  (void *)&options 
};

static const struct lws_protocol_vhost_options pvo_interrupted = {
      &pvo_options,
          NULL,
              "interrupted",       
                  (void *)&interrupted 
};

static const struct lws_protocol_vhost_options pvo = {
      NULL,                     
          &pvo_interrupted,          
              "lws-minimal-server-echo", 
                  ""                         
};

static int accepted_fd = 0;
static char client_ip[32] = "";
static int callback_server_echo(struct lws *wsi, enum lws_callback_reasons reason,
    void *user, void *in, size_t len)
{
  struct per_session_data *pss = (struct per_session_data *)user;
  struct vhd_handle *vhd = (struct vhd_handle *)lws_protocol_vh_priv_get(lws_get_vhost(wsi),
      lws_get_protocol(wsi));
  const struct msg *pmsg;
  struct msg amsg;
  int m, n, flags;

  char client_name[256] = "";
  switch (reason)
  {
    case LWS_CALLBACK_PROTOCOL_INIT:
      lwsl_warn("LWS_CALLBACK_PROTOCOL_INIT\n");
      vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_handle));

      if (!vhd)
        return -1;
      vhd->context = lws_get_context(wsi);
      vhd->vhost = lws_get_vhost(wsi);

      const struct lws_protocol_vhost_options *ind = lws_pvo_search((const struct lws_protocol_vhost_options*)in, "interrupted");

      if(ind) {
        lwsl_notice("ind it not null\n");
      } else {

        lwsl_notice("ind is null\n");
      }

      break;

    case LWS_CALLBACK_ESTABLISHED:
      lwsl_warn("LWS_CALLBACK_ESTABLISHED\n");
      pss->ring = lws_ring_create(sizeof(struct msg), RING_DEPTH, destroy_msg);

      pss->fd = accepted_fd;
      strcpy(pss->ip, client_ip);
      if (!pss->ring)
        return 1;
      lwsl_notice("ESTABLISHED IP(%s) FD(%d)\n", pss->ip, pss->fd);
      pss->tail = 0;
      break;
   case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
        lws_get_peer_addresses(wsi, (int)(long)in, client_name, sizeof(client_name) ,client_ip, sizeof(client_ip));
        accepted_fd = (int)(long)in;
        lwsl_notice("network connect from %s (%s)\n", client_name, client_ip);
        break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
      lwsl_warn("LWS_CALLBACK_SERVER_WRITEABLE\n");

      if (pss->write_consume_pending)
      {
        lws_ring_consume_single_tail(pss->ring, &pss->tail, 1);
        pss->write_consume_pending = 0;
      }

      pmsg = lws_ring_get_element(pss->ring, &pss->tail);
      if (!pmsg)
      {
        lwsl_user(" (nothing in ring)\n");
        break;
      }

      flags = lws_write_ws_flags(
          pmsg->binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT,
          pmsg->first, pmsg->final);

      m = lws_write(wsi, ((unsigned char *)pmsg->payload) + LWS_PRE, pmsg->len, flags);
      if (m < (int)pmsg->len)
      {
        lwsl_err("ERROR %d writing to ws socket\n", m);
        return -1;
      }

      lwsl_user(" wrote %d: flags: 0x%x first: %d final %d\n",
          m, flags, pmsg->first, pmsg->final);

      pss->write_consume_pending = 1;
      lws_callback_on_writable(wsi);

      if (pss->flow_controlled &&
          (int)lws_ring_get_count_free_elements(pss->ring) > RING_DEPTH - 5)
      {
        lws_rx_flow_control(wsi, 1);
        pss->flow_controlled = 0;
      }

      /*if ((*vhd->options & 1) && pmsg && pmsg->final)
        pss->completed = 1;*/

      break;

    case LWS_CALLBACK_RECEIVE:
      lwsl_user("LWS_CALLBACK_RECEIVE: %4d (rpp %5d, first %d, "
          "last %d, bin %d, msglen %d (+ %d = %d))\n",
          (int)len, (int)lws_remaining_packet_payload(wsi),
          lws_is_first_fragment(wsi),
          lws_is_final_fragment(wsi),
          lws_frame_is_binary(wsi), pss->msglen, (int)len,
          (int)pss->msglen + (int)len);

      amsg.first = lws_is_first_fragment(wsi);
      amsg.final = lws_is_final_fragment(wsi);
      amsg.binary = lws_frame_is_binary(wsi);
      n = (int)lws_ring_get_count_free_elements(pss->ring);
      if (!n)
      {
        lwsl_user("dropping!\n");
        break;
      }

      if (amsg.final)
        pss->msglen = 0;
      else
        pss->msglen += len;
      amsg.len = len;
      /* notice we over-allocate by LWS_PRE */
      amsg.payload = malloc(LWS_PRE + len);
      if (!amsg.payload)
      {
        lwsl_user("OOM: dropping\n");
        break;
      }

      memcpy((char *)amsg.payload + LWS_PRE, in, len);
      if (!lws_ring_insert(pss->ring, &amsg, 1))
      {
        destroy_msg(&amsg);
        lwsl_user("dropping!\n");
        break;
      }

      lws_callback_on_writable(wsi);

      if (n < 3 && !pss->flow_controlled)
      {
        pss->flow_controlled = 1;
        lws_rx_flow_control(wsi, 0);
      }
      break;

    case LWS_CALLBACK_CLOSED:
      lwsl_user("LWS_CALLBACK_CLOSED\n");
      lwsl_notice("CLOSED fd(%d)\n", pss->fd);
      lws_ring_destroy(pss->ring);
      lws_cancel_service(lws_get_context(wsi));

      /*if (*vhd->options & 1)
      {
        if (!*vhd->inerrupted)
          *vhd->interrupted = 1 + pss->completed;
        lws_cancel_service(lws_get_context(wsi));
      }*/
      break;

    default:
      break;
  }
  return 0;
}
static struct lws_protocols protocols[] = {
  {"webserver_echo",
    callback_server_echo,
    sizeof(struct per_session_data),
    1024,
    0, NULL, 0},
  {NULL, NULL, 0, 0}};


void sigint_handler(int sig)
{
  interrupted = 1;
}

int main(int argc, const char **argv)
{
  struct lws_context_creation_info info;
  struct lws_context *context;
  const char *p;
  int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

  signal(SIGINT, sigint_handler);

  lws_set_log_level(logs, NULL);

  lwsl_user("[-p port] [-o (once)]\n");

  if ((p = lws_cmdline_option(argc, argv, "-p")))
    port = atoi(p);

  memset(&info, 0, sizeof(info));
  info.port = port;
  info.protocols = protocols;
  info.pvo = &pvo;
  info.pt_serv_buf_size = 32 * 1024;
  info.options = LWS_SERVER_OPTION_VALIDATE_UTF8 |
    LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

  context = lws_create_context(&info);
  if (!context)
  {
    lwsl_err("lws init failed\n");
    return 1;
  }

  while (n >= 0 && !interrupted)
  {
    n = lws_service(context, 0);
  }

  lws_context_destroy(context);

  lwsl_user("Completed %s\n", interrupted == 1 ? "OK" : "failed");

  return interrupted != 1;
}
