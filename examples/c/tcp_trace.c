#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "tcp_trace.h"
#include "tcp_trace.skel.h"

static struct env {
	pid_t pid;
	__u16 lport;
} env;

static volatile bool exiting = false;
static bool verbose = false;

static void sig_handler(int sig)
{
	exiting = true;
}

const char *argp_program_version = "tcp_trace 0.1";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"\nTrace TCP.\n"
"\n"
"USAGE: tcp_trace [--help] [-t] [-p PID] [-l LPORT]\n"
"\n"
"EXAMPLES:\n"
"    tcp_trace              # summarize on-CPU time as a histogram\n"
"    tcp_trace -p 185       # trace PID 185 only\n"
"    tcp_trace -l 8080      # trace LPORT 8080 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "lport", 'l', "LPORT", 0, "Trace this LPORT only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'l':
		errno = 0;
		env.lport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid lport: %s\n", arg);
			argp_usage(state);
		}
		//env.lport = htons(env.lport);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr;
		d.x4.s_addr = e->daddr;
	}else {
		fprintf(stderr, "broken event: event->af=%d", e->af);
		return -1;
	}

	printf("%-16s %-4s %-16s %-6u %-16s %-6u %-10d %-6d %-10u %-6u %-8u %-10u\n",
		e->comm, e->rxtx ? "RX" : "TX",
		inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
		inet_ntop(e->af, &d, dst, sizeof(dst)),ntohs(e->dport),
		e->size_goal, e->mss, e->skb_len, e->wmem, e->true_size, e->skb_data_len);

	return 0;
}

int app_run(void)
{
	struct ring_buffer *rb = NULL;
	struct tcp_trace_bpf *skel;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	skel = tcp_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	skel->rodata->targ_tgid = env.pid;
	skel->rodata->targ_lport = env.lport;

	/* Load & verify BPF programs */
	int err = tcp_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = tcp_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

		/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-16s %-4s %-16s %-6s %-16s %-6s %-10s %-6s %-10s %-6s %-8s %-10s\n", 
	"COMM", "RXTX", "SADDR", "LPORT", "DADDR", "DPORT", "SIZE_GOAL", "MSS", "LEN", "WMEM", "TRUESIZE", "DATA_LEN");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	tcp_trace_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
 
int main(int argc, char **argv)
{

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

   return app_run();
}