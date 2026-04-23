package seeds

import (
	"github.com/shridarpatil/whatomate/internal/models"
	"github.com/zerodha/logf"
	"gorm.io/gorm"
)

// NormalizeLegacyFlowStepNames performs a safe one-time normalization for legacy
// step names in existing (including custom) flows stored in DB.
//
// It only applies when a known legacy pattern is detected to avoid renaming
// unrelated user-defined flows.
func NormalizeLegacyFlowStepNames(db *gorm.DB, lo logf.Logger) error {
	var flows []models.ChatbotFlow
	if err := db.Preload("Steps", func(tx *gorm.DB) *gorm.DB {
		return tx.Order("step_order ASC")
	}).Find(&flows).Error; err != nil {
		return err
	}

	for _, flow := range flows {
		renameMap := detectLegacyRenameMap(flow.Steps)
		if len(renameMap) == 0 {
			continue
		}

		if err := applyRenameMapToFlow(db, flow.ID, flow.Steps, renameMap); err != nil {
			return err
		}

		lo.Info("Normalized legacy step names", "flow_id", flow.ID, "flow_name", flow.Name, "renamed_steps", len(renameMap))
	}

	return nil
}

func detectLegacyRenameMap(steps []models.ChatbotFlowStep) map[string]string {
	has := make(map[string]bool, len(steps))
	for _, s := range steps {
		has[s.StepName] = true
	}

	// Legacy Plan Selection pattern
	if has["basic_reply"] && has["pro_reply"] && has["advance_reply"] {
		return map[string]string{
			"step_1":       "plan_selection_prompt",
			"basic_reply":  "basic_plan_reply",
			"pro_reply":    "pro_plan_reply",
			"advance_reply": "advance_plan_reply",
			"step_5":       "payment_instruction",
		}
	}

	// Legacy Burned Buyer pattern
	if has["step_3a"] && has["step_3b"] && has["step_6_yes"] && has["step_6_no"] {
		return map[string]string{
			"step_1":    "agency_background_question",
			"step_2":    "strategy_clarity_question",
			"step_3a":   "strategy_present_branch",
			"step_3b":   "execution_only_branch",
			"step_4":    "mentored_execution_reframe",
			"step_5":    "weekly_review_hook_question",
			"step_6_yes": "interested_next_step",
			"step_6_no":  "not_interested_soft_exit",
		}
	}

	return nil
}

func applyRenameMapToFlow(db *gorm.DB, flowID interface{}, steps []models.ChatbotFlowStep, renameMap map[string]string) error {
	tx := db.Begin()

	// 1) Rename step_name
	for _, step := range steps {
		newName, ok := renameMap[step.StepName]
		if !ok || newName == "" || newName == step.StepName {
			continue
		}
		if err := tx.Model(&models.ChatbotFlowStep{}).
			Where("id = ?", step.ID).
			Update("step_name", newName).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// 2) Update references (next_step + conditional_next values)
	var fresh []models.ChatbotFlowStep
	if err := tx.Where("flow_id = ?", flowID).Find(&fresh).Error; err != nil {
		tx.Rollback()
		return err
	}

	for _, step := range fresh {
		updates := map[string]interface{}{}

		if mapped, ok := renameMap[step.NextStep]; ok && step.NextStep != "" {
			updates["next_step"] = mapped
		}

		if len(step.ConditionalNext) > 0 {
			changed := false
			newCond := models.JSONB{}
			for k, v := range step.ConditionalNext {
				if target, ok := v.(string); ok {
					if mapped, found := renameMap[target]; found {
						newCond[k] = mapped
						changed = true
					} else {
						newCond[k] = v
					}
				} else {
					newCond[k] = v
				}
			}
			if changed {
				updates["conditional_next"] = newCond
			}
		}

		if len(updates) > 0 {
			if err := tx.Model(&models.ChatbotFlowStep{}).
				Where("id = ?", step.ID).
				Updates(updates).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
	}

	return tx.Commit().Error
}

