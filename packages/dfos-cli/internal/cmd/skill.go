package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/skill"
	"github.com/spf13/cobra"
)

func newSkillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Print or install the DFOS skill for Claude Code",
		Long: "The DFOS skill teaches an AI coding agent (Claude Code) how to drive this CLI.\n" +
			"It is embedded in this binary, so the skill always matches the installed version.\n\n" +
			"  dfos skill print              # write the skill to stdout\n" +
			"  dfos skill install            # install into ./.claude/skills/dfos/SKILL.md\n" +
			"  dfos skill install --global   # install into ~/.claude/skills/dfos/SKILL.md",
	}
	cmd.AddCommand(newSkillPrintCmd())
	cmd.AddCommand(newSkillInstallCmd())
	return cmd
}

func newSkillPrintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "print",
		Short: "Print the skill (SKILL.md) to stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(skill.Markdown)
			return nil
		},
	}
}

func newSkillInstallCmd() *cobra.Command {
	var global bool
	var force bool
	var dir string

	c := &cobra.Command{
		Use:   "install",
		Short: "Install the skill into a .claude/skills/dfos/ directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			base := dir
			if base == "" {
				if global {
					home, err := os.UserHomeDir()
					if err != nil {
						return fmt.Errorf("resolve home directory: %w", err)
					}
					base = filepath.Join(home, ".claude", "skills", "dfos")
				} else {
					base = filepath.Join(".claude", "skills", "dfos")
				}
			}

			target := filepath.Join(base, "SKILL.md")
			if _, err := os.Stat(target); err == nil && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", target)
			}
			if err := os.MkdirAll(base, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", base, err)
			}
			if err := os.WriteFile(target, []byte(skill.Markdown), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", target, err)
			}

			if jsonFlag {
				outputJSON(map[string]string{"path": target, "version": Version})
			} else {
				fmt.Printf("Installed DFOS skill -> %s (dfos %s)\n", target, Version)
			}
			return nil
		},
	}

	c.Flags().BoolVar(&global, "global", false, "Install to ~/.claude/skills (all projects) instead of ./.claude/skills")
	c.Flags().BoolVar(&force, "force", false, "Overwrite an existing SKILL.md")
	c.Flags().StringVar(&dir, "dir", "", "Custom target directory (overrides the default and --global)")
	return c
}
