package seeds

import (
	"github.com/google/uuid"
	"github.com/shridarpatil/whatomate/internal/models"
	"github.com/zerodha/logf"
	"gorm.io/gorm"
)

const (
	SystemPlanSelectionFlowName = "System: Plan Selection (Default)"
	SystemBurnedBuyerFlowName   = "System: Burned Buyer Sequence (Default)"
	SystemLeadCaptureFlowName   = "System: Lead Capture (Default)"
	SystemMasterSalesFlowName   = "System: Master Sales Qualification (Default)"
	SystemMentorFitFlowName     = "System: Mentor Fit Assessment (Default)"
	SystemMentorBookingFlowName = "System: Mentor Session Booking (Default)"
	SystemMentorReadinessFlowName = "System: Mentor Readiness Score (Default)"
	SystemMentorObjectionFlowName = "System: Mentor Objection Handling (Default)"
	SystemMentorGrowthPlanFlowName = "System: Mentor Growth Plan Intake (Default)"
	SystemRevenueReengagementFlowName = "System: Revenue Re-engagement Qualifier (Default)"
)

// EnsureDefaultChatbotFlows creates built-in chatbot flows for every organization.
// It is idempotent and will not duplicate flows if they already exist.
func EnsureDefaultChatbotFlows(db *gorm.DB, lo logf.Logger) error {
	var orgs []models.Organization
	if err := db.Select("id").Find(&orgs).Error; err != nil {
		return err
	}

	for _, org := range orgs {
		if err := ensureDefaultPlanSelectionFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureBurnedBuyerFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureLeadCaptureFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMasterSalesQualificationFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMentorFitAssessmentFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMentorSessionBookingFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMentorReadinessScoreFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMentorObjectionHandlingFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureMentorGrowthPlanIntakeFlow(db, lo, org.ID); err != nil {
			return err
		}
		if err := ensureRevenueReengagementFlow(db, lo, org.ID); err != nil {
			return err
		}
	}

	return nil
}

func ensureDefaultPlanSelectionFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel: models.BaseModel{ID: flowID},
		OrganizationID:     orgID,
		WhatsAppAccount:    "",
		Name:               SystemPlanSelectionFlowName,
		IsEnabled:          true,
		Description:        "Built-in default flow seeded from codebase (v1).",
		TriggerKeywords:    models.StringArray{"plans", "plan"},
		InitialMessage:     "Thanks for contacting us! Please choose a plan.",
		CompletionMessage:  "Thank you! If you need anything else, type hi.",
		OnCompleteAction:   "none",
		CompletionConfig:   models.JSONB{},
		TimeoutMessage:     "",
		CancelKeywords:     models.StringArray{},
		PanelConfig:        models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "plan_selection_prompt",
			StepOrder:       1,
			Message:         "Please select a plan:",
			MessageType:     models.FlowStepTypeButtons,
			InputType:       models.InputTypeSelect,
			InputConfig:     models.JSONB{"options": []string{"Basic", "Pro", "Advance"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "basic", "title": "Basic", "type": "reply"},
				map[string]interface{}{"id": "pro", "title": "Pro", "type": "reply"},
				map[string]interface{}{"id": "advance", "title": "Advance", "type": "reply"},
			},
			StoreAs:         "selected_plan",
			ConditionalNext: models.JSONB{"basic": "basic_plan_reply", "pro": "pro_plan_reply", "advance": "advance_plan_reply"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "basic_plan_reply",
			StepOrder:       2,
			Message:         "Basic plan starts at just Rs 1999.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "payment_instruction",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "pro_plan_reply",
			StepOrder:       3,
			Message:         "Pro plan starts at just Rs 4999.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "payment_instruction",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "advance_plan_reply",
			StepOrder:       4,
			Message:         "Advance plan starts at just Rs 9999.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "payment_instruction",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "payment_instruction",
			StepOrder:       5,
			Message:         "Thanks for choosing the plan. Please go ahead and make your payment.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
	}

	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureBurnedBuyerFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemBurnedBuyerFlowName,
		IsEnabled:         true,
		Description:       "Trust rebuild sequence with automated no-reply follow-ups at +1/+3/+5 days.",
		TriggerKeywords:   models.StringArray{"burned", "agency"},
		InitialMessage:    "",
		CompletionMessage: "Thanks — if you want, we can review your numbers together.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "agency_background_question",
			StepOrder:       1,
			Message:         "Hey {{name}}—quick question.\nHave you worked with agencies before or handling growth in-house?",
			MessageType:     models.FlowStepTypeButtons,
			InputType:       models.InputTypeSelect,
			InputConfig:     models.JSONB{"options": []string{"Worked with agencies", "Handling in-house"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "agencies", "title": "Worked with agencies", "type": "reply"},
				map[string]interface{}{"id": "in_house", "title": "Handling in-house", "type": "reply"},
			},
			StoreAs:         "growth_setup",
			NextStep:        "strategy_clarity_question",
			ConditionalNext: models.JSONB{"agencies": "strategy_clarity_question", "in_house": "strategy_clarity_question"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "strategy_clarity_question",
			StepOrder:       2,
			Message:         "Got it.\nDid they actually explain strategy or mostly just execute (like running ads)?",
			MessageType:     models.FlowStepTypeButtons,
			InputType:       models.InputTypeSelect,
			InputConfig:     models.JSONB{"options": []string{"Explained strategy", "Mostly executed"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "strategy", "title": "Explained strategy", "type": "reply"},
				map[string]interface{}{"id": "execute", "title": "Mostly executed", "type": "reply"},
			},
			StoreAs:         "strategy_quality",
			ConditionalNext: models.JSONB{"strategy": "strategy_present_branch", "execute": "execution_only_branch"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "strategy_present_branch",
			StepOrder:       3,
			Message:         "Great—they did share strategy.\nNext step is execution with weekly review loops so spend translates into results.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "mentored_execution_reframe",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "execution_only_branch",
			StepOrder:       4,
			Message:         "Yeah, that's the common gap.\nExecution without strategy = wasted spend.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "mentored_execution_reframe",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "mentored_execution_reframe",
			StepOrder:       5,
			Message:         "We do it differently—mentors guide you and help you execute.\nSo you understand what's working.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			NextStep:        "weekly_review_hook_question",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "weekly_review_hook_question",
			StepOrder:       6,
			Message:         "If someone reviewed your numbers weekly and told you exactly what to fix—would that help?",
			MessageType:     models.FlowStepTypeButtons,
			InputType:       models.InputTypeSelect,
			InputConfig:     models.JSONB{"options": []string{"Yes, that helps", "Not right now"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "yes", "title": "Yes, that helps", "type": "reply"},
				map[string]interface{}{"id": "no", "title": "Not right now", "type": "reply"},
			},
			StoreAs:         "weekly_review_interest",
			ConditionalNext: models.JSONB{"yes": "interested_next_step", "no": "not_interested_soft_exit"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "interested_next_step",
			StepOrder:       7,
			Message:         "Perfect. Share your current monthly revenue/ad spend and we can suggest the next best fix.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeText,
			StoreAs:         "numbers_snapshot",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "not_interested_soft_exit",
			StepOrder:       8,
			Message:         "No worries. If you want, I can send a simple framework to evaluate agencies before you decide.",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeNone,
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
	}

	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureLeadCaptureFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemLeadCaptureFlowName,
		IsEnabled:         true,
		Description:       "Simple lead capture flow for contact qualification.",
		TriggerKeywords:   models.StringArray{"demo", "lead"},
		InitialMessage:    "Great—let's get your details quickly.",
		CompletionMessage: "Thanks! Our team will reach out soon.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "ask_name",
			StepOrder:       1,
			Message:         "What's your full name?",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeText,
			StoreAs:         "lead_name",
			NextStep:        "ask_business",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "ask_business",
			StepOrder:       2,
			Message:         "What's your business name?",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeText,
			StoreAs:         "business_name",
			NextStep:        "ask_goal",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:       models.BaseModel{ID: uuid.New()},
			FlowID:          flowID,
			StepName:        "ask_goal",
			StepOrder:       3,
			Message:         "What is your primary growth goal in the next 90 days?",
			MessageType:     models.FlowStepTypeText,
			InputType:       models.InputTypeText,
			StoreAs:         "growth_goal",
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
	}

	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMasterSalesQualificationFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMasterSalesFlowName,
		IsEnabled:         true,
		Description:       "Master qualification flow from stage to close with hot/warm/cold routing and no-reply follow-ups.",
		TriggerKeywords:   models.StringArray{"sales", "qualify"},
		InitialMessage:    "",
		CompletionMessage: "Thanks for sharing. If you want, I can help map your next best move.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "stage_entry_question",
			StepOrder:   1,
			Message:     "Hey {{name}} 👋\nJust wanted to understand—are you currently just starting out or already generating some revenue?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Just starting", "Doing some revenue"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "beginner", "title": "Just starting", "type": "reply"},
				map[string]interface{}{"id": "intermediate", "title": "Doing some revenue", "type": "reply"},
			},
			StoreAs:         "stage",
			ConditionalNext: models.JSONB{"beginner": "beginner_context_prompt", "intermediate": "intermediate_context_prompt"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "beginner_context_prompt",
			StepOrder:      2,
			Message:        "Got it 👍 starting phase.\nWhat are you trying to build exactly right now?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeText,
			StoreAs:        "idea",
			NextStep:       "problem_discovery_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "intermediate_context_prompt",
			StepOrder:      3,
			Message:        "Nice—that's a good place to be.\nWhat's the biggest challenge right now—growth, consistency, or scaling?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeText,
			StoreAs:        "problem",
			NextStep:       "problem_discovery_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "problem_discovery_question",
			StepOrder:   4,
			Message:     "Which one feels closest right now?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Traffic issue", "Conversion issue", "Consistency issue", "No clarity"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "traffic", "title": "Traffic issue", "type": "reply"},
				map[string]interface{}{"id": "conversion", "title": "Conversion issue", "type": "reply"},
				map[string]interface{}{"id": "consistency", "title": "Consistency issue", "type": "reply"},
				map[string]interface{}{"id": "unclear", "title": "No clarity", "type": "reply"},
			},
			StoreAs: "problem_type",
			ConditionalNext: models.JSONB{
				"traffic":     "problem_traffic_reply",
				"conversion":  "problem_conversion_reply",
				"consistency": "problem_consistency_reply",
				"unclear":     "problem_unclear_reply",
			},
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "problem_traffic_reply",
			StepOrder:      5,
			Message:        "Got it—that's usually a top-of-funnel issue.\nAre you currently running ads, content, or both?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "past_efforts_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "problem_conversion_reply",
			StepOrder:      6,
			Message:        "That's actually a good sign.\nMeans the opportunity is in conversion, not traffic.\nHave you worked on your funnel or mostly driving visitors?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "past_efforts_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "problem_consistency_reply",
			StepOrder:      7,
			Message:        "Makes sense—that usually happens without a proper system.\nRight now is it more random efforts or a fixed strategy?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "past_efforts_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "problem_unclear_reply",
			StepOrder:      8,
			Message:        "Fair.\nUsually that means there's no clear roadmap yet.\nHave you been following any structured plan so far?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "past_efforts_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "past_efforts_question",
			StepOrder:   9,
			Message:     "Have you tried anything so far? Ads, agencies, self-learning, or nothing yet?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Ran ads", "Worked with agencies", "Learning myself", "Nothing yet"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "ads", "title": "Ran ads", "type": "reply"},
				map[string]interface{}{"id": "agency", "title": "Worked with agencies", "type": "reply"},
				map[string]interface{}{"id": "self", "title": "Learning myself", "type": "reply"},
				map[string]interface{}{"id": "none", "title": "Nothing yet", "type": "reply"},
			},
			StoreAs: "experience",
			ConditionalNext: models.JSONB{
				"ads":    "past_efforts_ads_reply",
				"agency": "past_efforts_agency_reply",
				"self":   "past_efforts_self_reply",
				"none":   "past_efforts_none_reply",
			},
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "past_efforts_ads_reply",
			StepOrder:      10,
			Message:        "Got it.\nDid you have a clear strategy behind it or mostly testing things?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "goal_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "past_efforts_agency_reply",
			StepOrder:      11,
			Message:        "Makes sense.\nDid they explain strategy or mostly execute for you?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "goal_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "past_efforts_self_reply",
			StepOrder:      12,
			Message:        "That's good initiative 👍\nBut yeah—it can get slow without direction.\nHave you been following any specific framework or just figuring it out?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "goal_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "past_efforts_none_reply",
			StepOrder:      13,
			Message:        "Perfect actually.\nMeans you can avoid a lot of common mistakes early.\nWant to do it the right way from start.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "goal_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "goal_question",
			StepOrder:   14,
			Message:     "Where are you trying to reach in the next 2–3 months?\nAny target in mind?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Clear goal", "Just grow", "Not sure yet"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "clear", "title": "Clear goal", "type": "reply"},
				map[string]interface{}{"id": "vague", "title": "Just grow", "type": "reply"},
				map[string]interface{}{"id": "none", "title": "Not sure yet", "type": "reply"},
			},
			StoreAs:         "goal_clarity",
			ConditionalNext: models.JSONB{"clear": "goal_clear_reply", "vague": "goal_vague_reply", "none": "goal_none_reply"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "goal_clear_reply",
			StepOrder:      15,
			Message:        "Nice—that's a solid goal.\nDefinitely achievable with the right system.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "readiness_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "goal_vague_reply",
			StepOrder:      16,
			Message:        "Got it.\nIf we had to define it—would you say more revenue, more leads, or more consistency?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "readiness_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "goal_none_reply",
			StepOrder:      17,
			Message:        "That's fine.\nWe can actually help define a clear direction as well.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "readiness_question",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "readiness_question",
			StepOrder:   18,
			Message:     "If you had the right guidance—\nWould you want to start working on this immediately or still exploring?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Immediately", "Still exploring", "Not now"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "hot", "title": "Immediately", "type": "reply"},
				map[string]interface{}{"id": "warm", "title": "Still exploring", "type": "reply"},
				map[string]interface{}{"id": "cold", "title": "Not now", "type": "reply"},
			},
			StoreAs:         "intent",
			ConditionalNext: models.JSONB{"hot": "close_hot", "warm": "blocker_question", "cold": "nurture_message"},
			RetryOnInvalid:  true,
			MaxRetries:      3,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "blocker_question",
			StepOrder:   19,
			Message:     "Just to understand better—\nWhat do you feel is stopping you right now?\nTime, clarity, skills, money, or something else?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Time", "Money", "Skills", "Clarity", "Something else"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "time", "title": "Time", "type": "reply"},
				map[string]interface{}{"id": "money", "title": "Money", "type": "reply"},
				map[string]interface{}{"id": "skills", "title": "Skills", "type": "reply"},
				map[string]interface{}{"id": "clarity", "title": "Clarity", "type": "reply"},
				map[string]interface{}{"id": "other", "title": "Something else", "type": "reply"},
			},
			StoreAs: "blocker",
			ConditionalNext: models.JSONB{
				"time":    "blocker_time_reply",
				"money":   "blocker_money_reply",
				"skills":  "blocker_skills_reply",
				"clarity": "blocker_clarity_reply",
				"other":   "blocker_other_reply",
			},
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "blocker_time_reply",
			StepOrder:      20,
			Message:        "Makes sense—time is usually the first blocker.\nThat's where guided execution becomes a shortcut.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "close_warm",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "blocker_money_reply",
			StepOrder:      21,
			Message:        "Totally fair.\nUsually the bigger cost is wasted spend without direction.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "close_warm",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "blocker_skills_reply",
			StepOrder:      22,
			Message:        "That's common.\nLearning with implementation support usually closes this gap fast.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "close_warm",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "blocker_clarity_reply",
			StepOrder:      23,
			Message:        "Got it—that's actually the main gap for most people.\nOnce clarity is solved, growth gets easier.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "close_warm",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "blocker_other_reply",
			StepOrder:      24,
			Message:        "Got it—that's helpful context.\nOnce the core blocker is solved, growth becomes much easier.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			NextStep:       "close_warm",
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "close_hot",
			StepOrder:      25,
			Message:        "Got a clear picture now 👍\nBased on what you shared, I think we can help you.\nLet's jump on a quick 15-min call and map this out?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "close_warm",
			StepOrder:      26,
			Message:        "Happy to break this down for you properly.\nWant me to show how this would work for your case?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "nurture_message",
			StepOrder:      27,
			Message:        "No rush 👍\nI'll share some useful insights here that might help you.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			RetryOnInvalid: true,
			MaxRetries:     3,
		},
	}

	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMentorFitAssessmentFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMentorFitFlowName,
		IsEnabled:         true,
		Description:       "Mentor-led fit assessment to identify stage, commitment, and support needs.",
		TriggerKeywords:   models.StringArray{"fit", "mentorfit"},
		InitialMessage:    "Great to connect. Let's see if mentor support is the right fit for you.",
		CompletionMessage: "Thanks. Based on this, our mentor team will suggest the best next step.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "current_stage", StepOrder: 1, Message: "Which stage are you in right now?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Beginner", "Doing revenue", "Scaling"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "beginner", "title": "Beginner", "type": "reply"}, map[string]interface{}{"id": "revenue", "title": "Doing revenue", "type": "reply"}, map[string]interface{}{"id": "scaling", "title": "Scaling", "type": "reply"}}, StoreAs: "mentor_stage", NextStep: "core_goal", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "core_goal", StepOrder: 2, Message: "What is the one result you want from a mentor in the next 90 days?", MessageType: models.FlowStepTypeText, InputType: models.InputTypeText, StoreAs: "mentor_goal", NextStep: "weekly_commitment", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "weekly_commitment", StepOrder: 3, Message: "How many hours weekly can you commit to implementation?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"<3 hours", "3-7 hours", "7+ hours"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "low", "title": "<3 hours", "type": "reply"}, map[string]interface{}{"id": "mid", "title": "3-7 hours", "type": "reply"}, map[string]interface{}{"id": "high", "title": "7+ hours", "type": "reply"}}, StoreAs: "mentor_commitment_hours", NextStep: "support_type", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "support_type", StepOrder: 4, Message: "What support do you need most right now?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Strategy", "Execution", "Both"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "strategy", "title": "Strategy", "type": "reply"}, map[string]interface{}{"id": "execution", "title": "Execution", "type": "reply"}, map[string]interface{}{"id": "both", "title": "Both", "type": "reply"}}, StoreAs: "mentor_support_type", NextStep: "fit_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "fit_close", StepOrder: 5, Message: "Perfect. You look like a strong fit for mentor-led growth. Want us to map your action plan on a quick call?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Yes, book call", "Need details first"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "book", "title": "Yes, book call", "type": "reply"}, map[string]interface{}{"id": "details", "title": "Need details first", "type": "reply"}}, StoreAs: "mentor_fit_decision", RetryOnInvalid: true, MaxRetries: 3},
	}
	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMentorSessionBookingFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMentorBookingFlowName,
		IsEnabled:         true,
		Description:       "Lead booking flow for mentor discovery session qualification.",
		TriggerKeywords:   models.StringArray{"book", "session"},
		InitialMessage:    "Let's get your mentor session booked.",
		CompletionMessage: "Done. Our team will confirm your mentor slot shortly.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}
	steps := []models.ChatbotFlowStep{
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "full_name", StepOrder: 1, Message: "What's your full name?", MessageType: models.FlowStepTypeText, InputType: models.InputTypeText, StoreAs: "booking_name", NextStep: "business_type", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "business_type", StepOrder: 2, Message: "What best describes your business?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Service", "Ecommerce", "Content/Creator", "Other"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "service", "title": "Service", "type": "reply"}, map[string]interface{}{"id": "ecom", "title": "Ecommerce", "type": "reply"}, map[string]interface{}{"id": "creator", "title": "Content/Creator", "type": "reply"}, map[string]interface{}{"id": "other", "title": "Other", "type": "reply"}}, StoreAs: "booking_business_type", NextStep: "monthly_revenue_band", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "monthly_revenue_band", StepOrder: 3, Message: "Current monthly revenue range?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Pre-revenue", "<1L", "1L-10L", "10L+"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "pre", "title": "Pre-revenue", "type": "reply"}, map[string]interface{}{"id": "small", "title": "<1L", "type": "reply"}, map[string]interface{}{"id": "mid", "title": "1L-10L", "type": "reply"}, map[string]interface{}{"id": "high", "title": "10L+", "type": "reply"}}, StoreAs: "booking_revenue_band", NextStep: "priority_problem", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "priority_problem", StepOrder: 4, Message: "What's your top priority for the mentor call?", MessageType: models.FlowStepTypeText, InputType: models.InputTypeText, StoreAs: "booking_priority_problem", NextStep: "preferred_time", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "preferred_time", StepOrder: 5, Message: "Preferred call window?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Morning", "Afternoon", "Evening"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "morning", "title": "Morning", "type": "reply"}, map[string]interface{}{"id": "afternoon", "title": "Afternoon", "type": "reply"}, map[string]interface{}{"id": "evening", "title": "Evening", "type": "reply"}}, StoreAs: "booking_preferred_time", RetryOnInvalid: true, MaxRetries: 3},
	}
	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMentorReadinessScoreFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMentorReadinessFlowName,
		IsEnabled:         true,
		Description:       "Pre-qualification flow to score lead readiness for mentor onboarding.",
		TriggerKeywords:   models.StringArray{"ready", "readiness"},
		InitialMessage:    "Quick readiness check before mentor onboarding.",
		CompletionMessage: "Thanks. We'll classify your readiness and share the best path.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}
	steps := []models.ChatbotFlowStep{
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "clarity_check", StepOrder: 1, Message: "How clear are you about your next 90-day business goal?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Very clear", "Somewhat clear", "Not clear"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "high", "title": "Very clear", "type": "reply"}, map[string]interface{}{"id": "mid", "title": "Somewhat clear", "type": "reply"}, map[string]interface{}{"id": "low", "title": "Not clear", "type": "reply"}}, StoreAs: "readiness_clarity", NextStep: "implementation_habit", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "implementation_habit", StepOrder: 2, Message: "How consistently do you execute weekly action items?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Consistent", "On and off", "Rarely"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "consistent", "title": "Consistent", "type": "reply"}, map[string]interface{}{"id": "mixed", "title": "On and off", "type": "reply"}, map[string]interface{}{"id": "rare", "title": "Rarely", "type": "reply"}}, StoreAs: "readiness_execution", NextStep: "decision_speed", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "decision_speed", StepOrder: 3, Message: "How quickly can you implement mentor feedback?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Within 24h", "Within a week", "Not sure"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "fast", "title": "Within 24h", "type": "reply"}, map[string]interface{}{"id": "week", "title": "Within a week", "type": "reply"}, map[string]interface{}{"id": "unsure", "title": "Not sure", "type": "reply"}}, StoreAs: "readiness_speed", NextStep: "readiness_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "readiness_close", StepOrder: 4, Message: "Great. Based on this, would you like a mentor roadmap first or direct execution plan?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Roadmap first", "Execution plan"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "roadmap", "title": "Roadmap first", "type": "reply"}, map[string]interface{}{"id": "execution", "title": "Execution plan", "type": "reply"}}, StoreAs: "readiness_next_preference", RetryOnInvalid: true, MaxRetries: 3},
	}
	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMentorObjectionHandlingFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMentorObjectionFlowName,
		IsEnabled:         true,
		Description:       "Mentor-oriented objection handling flow for warm leads.",
		TriggerKeywords:   models.StringArray{"doubt", "objection"},
		InitialMessage:    "Totally fair — let's clear your biggest concern first.",
		CompletionMessage: "If helpful, we can walk through this on a short call.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}
	steps := []models.ChatbotFlowStep{
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "main_objection", StepOrder: 1, Message: "What's the biggest blocker right now?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Time", "Budget", "Not confident", "Need proof"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "time", "title": "Time", "type": "reply"}, map[string]interface{}{"id": "budget", "title": "Budget", "type": "reply"}, map[string]interface{}{"id": "confidence", "title": "Not confident", "type": "reply"}, map[string]interface{}{"id": "proof", "title": "Need proof", "type": "reply"}}, StoreAs: "objection_type", ConditionalNext: models.JSONB{"time": "reply_time", "budget": "reply_budget", "confidence": "reply_confidence", "proof": "reply_proof"}, RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "reply_time", StepOrder: 2, Message: "Understood. A mentor usually saves time by removing trial-and-error and giving exact priorities.", MessageType: models.FlowStepTypeText, InputType: models.InputTypeNone, NextStep: "objection_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "reply_budget", StepOrder: 3, Message: "Fair point. Most leads find the bigger cost is delayed growth and wasted experiments.", MessageType: models.FlowStepTypeText, InputType: models.InputTypeNone, NextStep: "objection_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "reply_confidence", StepOrder: 4, Message: "Makes sense. Mentor support is designed for this — clarity, accountability, and guided execution.", MessageType: models.FlowStepTypeText, InputType: models.InputTypeNone, NextStep: "objection_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "reply_proof", StepOrder: 5, Message: "Absolutely. We can walk through similar outcomes and the process mentors use case-by-case.", MessageType: models.FlowStepTypeText, InputType: models.InputTypeNone, NextStep: "objection_close", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "objection_close", StepOrder: 6, Message: "Would you like a quick mentor call to address this specifically for your case?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Yes", "Need more info"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "yes", "title": "Yes", "type": "reply"}, map[string]interface{}{"id": "info", "title": "Need more info", "type": "reply"}}, StoreAs: "objection_close_decision", RetryOnInvalid: true, MaxRetries: 3},
	}
	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureMentorGrowthPlanIntakeFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemMentorGrowthPlanFlowName,
		IsEnabled:         true,
		Description:       "Mentor intake flow to build a growth action plan from lead responses.",
		TriggerKeywords:   models.StringArray{"roadmap", "growthplan"},
		InitialMessage:    "Let's draft your mentor-led growth plan intake.",
		CompletionMessage: "Perfect. We'll convert this into a suggested mentor roadmap.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}
	steps := []models.ChatbotFlowStep{
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "current_offer", StepOrder: 1, Message: "What offer or product are you currently selling?", MessageType: models.FlowStepTypeText, InputType: models.InputTypeText, StoreAs: "plan_offer", NextStep: "acquisition_channel", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "acquisition_channel", StepOrder: 2, Message: "Primary acquisition channel right now?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Organic", "Paid Ads", "Referrals", "Mixed"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "organic", "title": "Organic", "type": "reply"}, map[string]interface{}{"id": "paid", "title": "Paid Ads", "type": "reply"}, map[string]interface{}{"id": "referral", "title": "Referrals", "type": "reply"}, map[string]interface{}{"id": "mixed", "title": "Mixed", "type": "reply"}}, StoreAs: "plan_channel", NextStep: "current_bottleneck", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "current_bottleneck", StepOrder: 3, Message: "Where is the main bottleneck today: lead generation, sales conversion, or retention?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Lead generation", "Sales conversion", "Retention"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "leadgen", "title": "Lead generation", "type": "reply"}, map[string]interface{}{"id": "conversion", "title": "Sales conversion", "type": "reply"}, map[string]interface{}{"id": "retention", "title": "Retention", "type": "reply"}}, StoreAs: "plan_bottleneck", NextStep: "goal_90_days", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "goal_90_days", StepOrder: 4, Message: "What target do you want to hit in the next 90 days?", MessageType: models.FlowStepTypeText, InputType: models.InputTypeText, StoreAs: "plan_90d_goal", NextStep: "mentor_expectation", RetryOnInvalid: true, MaxRetries: 3},
		{BaseModel: models.BaseModel{ID: uuid.New()}, FlowID: flowID, StepName: "mentor_expectation", StepOrder: 5, Message: "What do you expect from the mentor relationship most?", MessageType: models.FlowStepTypeButtons, InputType: models.InputTypeSelect, InputConfig: models.JSONB{"options": []string{"Clarity", "Accountability", "Execution help", "All three"}}, Buttons: models.JSONBArray{map[string]interface{}{"id": "clarity", "title": "Clarity", "type": "reply"}, map[string]interface{}{"id": "accountability", "title": "Accountability", "type": "reply"}, map[string]interface{}{"id": "execution", "title": "Execution help", "type": "reply"}, map[string]interface{}{"id": "all", "title": "All three", "type": "reply"}}, StoreAs: "plan_mentor_expectation", RetryOnInvalid: true, MaxRetries: 3},
	}
	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func ensureRevenueReengagementFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID) error {
	flowID := uuid.New()
	flow := models.ChatbotFlow{
		BaseModel:         models.BaseModel{ID: flowID},
		OrganizationID:    orgID,
		WhatsAppAccount:   "",
		Name:              SystemRevenueReengagementFlowName,
		IsEnabled:         true,
		Description:       "Lead qualification with revenue input, sales intent branch, and +1 day re-engagement ping on no reply.",
		TriggerKeywords:   models.StringArray{"revenue", "scaleup"},
		InitialMessage:    "",
		CompletionMessage: "Thanks, and if you have another query then feel free to reach out to us again here.",
		OnCompleteAction:  "none",
		CompletionConfig:  models.JSONB{},
		TimeoutMessage:    "",
		CancelKeywords:    models.StringArray{"stop", "cancel"},
		PanelConfig:       models.JSONB{},
	}

	steps := []models.ChatbotFlowStep{
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "ask_total_revenue",
			StepOrder:      1,
			Message:        "Great to connect. What is your current total monthly revenue?",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeText,
			StoreAs:        "reported_revenue",
			NextStep:       "ask_increase_sales_interest",
			RetryOnInvalid: true,
			MaxRetries:     5,
		},
		{
			BaseModel:   models.BaseModel{ID: uuid.New()},
			FlowID:      flowID,
			StepName:    "ask_increase_sales_interest",
			StepOrder:   2,
			Message:     "Would you like to increase sales?",
			MessageType: models.FlowStepTypeButtons,
			InputType:   models.InputTypeSelect,
			InputConfig: models.JSONB{"options": []string{"Yes", "Maybe later"}},
			Buttons: models.JSONBArray{
				map[string]interface{}{"id": "yes", "title": "Yes", "type": "reply"},
				map[string]interface{}{"id": "maybe_later", "title": "Maybe later", "type": "reply"},
			},
			StoreAs:         "sales_interest",
			ConditionalNext: models.JSONB{"yes": "sales_yes_branch", "maybe_later": "sales_maybe_later_branch"},
			RetryOnInvalid:  true,
			MaxRetries:      5,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "sales_yes_branch",
			StepOrder:      3,
			Message:        "Awsome, its a right time to start with our personalised sales meeting.\nHere is the link that you can join on Sunday at 9 to 10 AM in the Morning\nlink - EgZjaHJvbWUqDggAEEUYJxg7GIAEGIoFMg4IABBFGCcYOxiA",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeNone,
			SkipCondition:  "sales_interest != 'yes'",
			RetryOnInvalid: true,
			MaxRetries:     5,
		},
		{
			BaseModel:      models.BaseModel{ID: uuid.New()},
			FlowID:         flowID,
			StepName:       "sales_maybe_later_branch",
			StepOrder:      4,
			Message:        "No problem. If timing changes, just reply 'yes' and we'll continue from where you left off.",
			MessageType:    models.FlowStepTypeText,
			InputType:      models.InputTypeText,
			StoreAs:        "later_reason",
			SkipCondition:  "sales_interest != 'maybe_later'",
			RetryOnInvalid: true,
			MaxRetries:     5,
		},
	}

	return createOrUpdateSystemFlow(db, lo, orgID, flow, steps)
}

func createOrUpdateSystemFlow(db *gorm.DB, lo logf.Logger, orgID uuid.UUID, flow models.ChatbotFlow, steps []models.ChatbotFlowStep) error {
	var existing models.ChatbotFlow
	err := db.Where("organization_id = ? AND name = ?", orgID, flow.Name).First(&existing).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	tx := db.Begin()
	flowID := flow.ID
	if err == nil {
		// Existing system flow: update definition and replace steps.
		flowID = existing.ID
		updates := map[string]interface{}{
			"description":         flow.Description,
			"trigger_keywords":    flow.TriggerKeywords,
			"initial_message":     flow.InitialMessage,
			"completion_message":  flow.CompletionMessage,
			"on_complete_action":  flow.OnCompleteAction,
			"completion_config":   flow.CompletionConfig,
			"timeout_message":     flow.TimeoutMessage,
			"cancel_keywords":     flow.CancelKeywords,
			"panel_config":        flow.PanelConfig,
			"whats_app_account":   flow.WhatsAppAccount,
		}
		if err := tx.Model(&models.ChatbotFlow{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Where("flow_id = ?", existing.ID).Delete(&models.ChatbotFlowStep{}).Error; err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if err := tx.Create(&flow).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	for _, step := range steps {
		step.FlowID = flowID
		if err := tx.Create(&step).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}

	lo.Info("Synced system chatbot flow", "org_id", orgID, "flow_name", flow.Name)
	return nil
}

