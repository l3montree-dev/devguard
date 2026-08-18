package commands

import (
	"strings"

	"github.com/spf13/cobra"
)

var LogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Analyze log files",
	Long: `Analyze log files from any devguard component.

Supported formats (auto detected, override with --format):

  api       devguard-api / scanner (zerolog console writer)
  kratos    ory kratos (logfmt)
  postgres  postgresql server log
  web       devguard-web (Next.js server output)

Levels are normalised to DBG/INF/WRN/ERR/FTL across all formats, so --level and
the errors and timeline subcommands behave identically whichever log you point
them at. Logs collected with "kubectl logs --timestamps" are also accepted; the
prefix supplies the timestamp, which is the only way to place the web log on a
timeline.`,
}

func init() {
	var logFile, logFormatFlag string
	LogsCmd.PersistentFlags().StringVarP(&logFile, "file", "f", "devguard.log", "log file to analyze")
	LogsCmd.PersistentFlags().StringVarP(&logFormatFlag, "format", "F", "auto",
		"log format: "+strings.Join(formatNames(), ", "))

	var summaryNormalize bool
	var summaryTop int
	summary := &cobra.Command{
		Use:   "summary",
		Short: "Print level counts, top sources, and top messages",
		Long: `Print level counts, top sources, and top messages.

With --normalize, ids, addresses, durations and numbers in messages are replaced
by placeholders before grouping, so occurrences of the same kind of event are
counted together regardless of the request id or address they mention. Combine it
with --top to count a specific kind of failure:

  devguard-maint logs -f api.log summary -N --top 100 | grep "connection refused"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsSummary(logFile, logFormatFlag, summaryNormalize, summaryTop)
		},
	}
	summary.Flags().BoolVarP(&summaryNormalize, "normalize", "N", false,
		"group messages by kind, replacing ids, addresses, durations and numbers")
	summary.Flags().IntVarP(&summaryTop, "top", "t", 15, "how many sources and messages to list")

	var filterLevel, filterSource, filterContains string
	var filterLimit int
	filter := &cobra.Command{
		Use:   "filter",
		Short: "Filter log entries by level, source, or substring",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsFilter(logFile, logFormatFlag, filterLevel, filterSource, filterContains, filterLimit)
		},
	}
	filter.Flags().StringVarP(&filterLevel, "level", "l", "", "level: DBG, INF, WRN, ERR, FTL")
	filter.Flags().StringVarP(&filterSource, "source", "s", "", "source substring (api: file:line, postgres: pid, kratos: request path, web: error digest)")
	filter.Flags().StringVarP(&filterContains, "contains", "c", "", "substring the entry must contain")
	filter.Flags().IntVarP(&filterLimit, "limit", "n", 0, "max entries (0 = all)")

	var errLimit int
	errors := &cobra.Command{
		Use:   "errors",
		Short: "Print all ERR and FTL entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsErrors(logFile, logFormatFlag, errLimit)
		},
	}
	errors.Flags().IntVarP(&errLimit, "limit", "n", 0, "max entries (0 = all)")

	var timelineBucket, timelineLevel string
	timeline := &cobra.Command{
		Use:   "timeline",
		Short: "Bucket entries over time to find when something started",
		Long: `Bucket entries over time to find when something started.

The web log carries no timestamps unless collected with kubectl --timestamps, so
timeline cannot bucket it. The api log carries a wall clock with no date and no
zone (zerolog prints "2:11PM"), so its buckets are time of day: it is not
necessarily local time, and postgres and kratos both log absolute UTC.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsTimeline(logFile, logFormatFlag, timelineBucket, timelineLevel)
		},
	}
	timeline.Flags().StringVarP(&timelineBucket, "bucket", "b", "minute", "bucket size: second, minute, hour")
	timeline.Flags().StringVarP(&timelineLevel, "level", "l", "", "only count this level")

	formats := &cobra.Command{
		Use:   "formats",
		Short: "List supported formats and show what the given file detects as",
		Long: `List supported formats and show what the given file detects as.

Detection always runs on the file, independently of --format.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsFormats(logFile)
		},
	}

	var corr correlateOptions
	correlate := &cobra.Command{
		Use:   "correlate <file> <file> [file...]",
		Short: "Line up several logs on one timeline to see what happened where",
		Long: `Line up several logs on one timeline to see what happened where.

Each file is detected independently, so api, kratos, postgres and web logs can be
mixed freely. The matrix shows, per time bucket, how many entries each log
produced and how many of those were errors, so an error spike in one component
can be read against what every other component was doing at that instant.

Use --around to drop from the matrix into the actual interleaved lines.

Timestamps differ by component, which is the main source of wrong conclusions:

  postgres and kratos log absolute dates in UTC.
  the api log (zerolog console writer) prints a wall clock with no date and no
  timezone. It is anchored so its last entry lands on the last date seen in the
  dated logs, and is assumed to share their zone; correct that with --offset.
  Its timestamps have minute resolution, so api entries within a minute all sort
  at second :00 relative to postgres and kratos.
  the Next.js web log has no timestamps at all and cannot be aligned; re-collect
  it with "kubectl logs --timestamps" and it lines up like the rest.

Examples:
  devguard-maint logs correlate api.log kratos.log postgres.log
  devguard-maint logs correlate api.log kratos.log --only-errors
  devguard-maint logs correlate api.log kratos.log --around 14:11 --window 90s
  devguard-maint logs correlate api.log kratos.log --offset api=+2h`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return logsCorrelate(args, logFormatFlag, corr)
		},
	}
	correlate.Flags().StringVarP(&corr.bucket, "bucket", "b", "minute", "bucket size: second, minute, hour")
	correlate.Flags().StringVarP(&corr.level, "level", "l", "", "only count this level")
	correlate.Flags().BoolVarP(&corr.onlyErrors, "only-errors", "e", false, "only show buckets containing ERR or FTL")
	correlate.Flags().StringVar(&corr.around, "around", "", "drill into the entries around this time (e.g. 14:11)")
	correlate.Flags().StringVar(&corr.window, "window", "1m", "half-width of the --around window")
	correlate.Flags().StringVar(&corr.date, "date", "", "anchor undated logs to this date (YYYY-MM-DD)")
	correlate.Flags().StringArrayVar(&corr.offsets, "offset", nil, "shift a log onto the shared timeline, e.g. --offset api=+2h")

	LogsCmd.AddCommand(summary, filter, errors, timeline, formats, correlate)
}
