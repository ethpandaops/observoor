package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/observoor/internal/agent"
	"github.com/ethpandaops/observoor/internal/version"
)

var (
	cfgFile  string
	logLevel string
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observoor",
		Short: "eBPF Ethereum node observability agent",
		Long: `observoor is an eBPF-based agent that monitors Ethereum
execution and consensus layer processes at the kernel level,
aggregating events per Ethereum slot. Zero client changes required.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          run,
	}

	cmd.Flags().StringVar(
		&cfgFile, "config", "",
		"path to config file (required)",
	)
	cmd.Flags().StringVar(
		&logLevel, "log-level", "",
		"override log level (debug, info, warn, error)",
	)

	if err := cmd.MarkFlagRequired("config"); err != nil {
		fmt.Fprintf(os.Stderr, "error marking flag required: %v\n", err)
		os.Exit(1)
	}

	cmd.AddCommand(versionCmd())

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.FullWithPlatform())
		},
	}
}

func run(cmd *cobra.Command, args []string) error {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	cfg, err := agent.LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI flag overrides config file.
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("parsing log level %q: %w", cfg.LogLevel, err)
	}

	log.SetLevel(level)

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	a, err := agent.New(log, cfg)
	if err != nil {
		return fmt.Errorf("creating agent: %w", err)
	}

	log.Info("Starting observoor agent")

	if err := a.Start(ctx); err != nil {
		return fmt.Errorf("starting agent: %w", err)
	}

	<-ctx.Done()

	log.Info("Shutting down observoor agent")

	if err := a.Stop(); err != nil {
		log.WithError(err).Error("Error during shutdown")
		return fmt.Errorf("stopping agent: %w", err)
	}

	log.Info("Shutdown complete")

	return nil
}
