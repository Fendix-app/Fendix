package i18n

// IsBeta reports whether a supported language is still a machine-translated
// beta awaiting native-speaker security review (F-I3). Arabic ships as a
// TRANSLATION_REVIEW_NEEDED baseline (see Arabic() and i18n.go's translation
// policy), so it's beta until that review clears. English is the source
// language and is never beta. Unknown codes are not beta — they fall back to
// English at render time, so there's nothing unreviewed to warn about.
//
// The CLI uses this to decide whether to emit the "machine-translated, beta"
// notice; the gate itself lives in reporters.ResolveLang.
func IsBeta(lang string) bool {
	switch normalize(lang) {
	case "ar":
		return true
	default:
		return false
	}
}

// Arabic returns the Arabic Strings. Every value is marked
// TRANSLATION_REVIEW_NEEDED in the comments — a native-speaker
// security professional must review and replace before Fendix is
// promoted to public Arabic-localised release. See
// `RISKS.md` (Arabic translation review).
//
// Numerals stay Western Arabic (0-9), not Eastern Arabic (٠-٩),
// per Sprint 10's risk-register decision.
func Arabic() Strings {
	return Strings{
		ReportTitle:       "تقرير الأمان من Fendix",             // TRANSLATION_REVIEW_NEEDED
		ScanSubtitle:      "{target} — مسح {mode} — {duration}", // TRANSLATION_REVIEW_NEEDED
		GeneratedByFendix: "تم إنشاء التقرير بواسطة Fendix",     // TRANSLATION_REVIEW_NEEDED

		SeverityCritical: "حرج",    // TRANSLATION_REVIEW_NEEDED
		SeverityHigh:     "عالي",   // TRANSLATION_REVIEW_NEEDED
		SeverityMedium:   "متوسط",  // TRANSLATION_REVIEW_NEEDED
		SeverityLow:      "منخفض",  // TRANSLATION_REVIEW_NEEDED
		SeverityInfo:     "معلومة", // TRANSLATION_REVIEW_NEEDED

		ConfidenceHigh:   "عالية",  // TRANSLATION_REVIEW_NEEDED
		ConfidenceMedium: "متوسطة", // TRANSLATION_REVIEW_NEEDED
		ConfidenceLow:    "منخفضة", // TRANSLATION_REVIEW_NEEDED

		SectionSummary:     "ملخص",         // TRANSLATION_REVIEW_NEEDED
		SectionFindings:    "النتائج",      // TRANSLATION_REVIEW_NEEDED
		SectionRemediation: "خطة المعالجة", // TRANSLATION_REVIEW_NEEDED
		SectionEvidence:    "الدليل",       // TRANSLATION_REVIEW_NEEDED
		SectionReferences:  "المراجع",      // TRANSLATION_REVIEW_NEEDED
		SectionMetadata:    "بيانات الفحص", // TRANSLATION_REVIEW_NEEDED
		ColumnID:           "المعرف",       // TRANSLATION_REVIEW_NEEDED
		ColumnTitle:        "العنوان",      // TRANSLATION_REVIEW_NEEDED
		ColumnSeverity:     "الخطورة",      // TRANSLATION_REVIEW_NEEDED
		ColumnLocation:     "الموقع",       // TRANSLATION_REVIEW_NEEDED
		ColumnFix:          "الإصلاح",      // TRANSLATION_REVIEW_NEEDED

		SortByLabel:        "ترتيب حسب:",                  // TRANSLATION_REVIEW_NEEDED
		SortBySeverity:     "الخطورة",                     // TRANSLATION_REVIEW_NEEDED
		SortByEndpoint:     "النقطة النهائية",             // TRANSLATION_REVIEW_NEEDED
		SortBySource:       "المصدر",                      // TRANSLATION_REVIEW_NEEDED
		ExpandAll:          "توسيع الكل",                  // TRANSLATION_REVIEW_NEEDED
		CollapseAll:        "طي الكل",                     // TRANSLATION_REVIEW_NEEDED
		FieldEvidence:      "الدليل",                      // TRANSLATION_REVIEW_NEEDED
		FieldFix:           "الإصلاح",                     // TRANSLATION_REVIEW_NEEDED
		FieldSource:        "المصدر",                      // TRANSLATION_REVIEW_NEEDED
		FieldCategory:      "الفئة",                       // TRANSLATION_REVIEW_NEEDED
		FieldConfidence:    "الثقة",                       // TRANSLATION_REVIEW_NEEDED
		FieldAffected:      "النقاط النهائية المتأثرة",    // TRANSLATION_REVIEW_NEEDED
		FieldReachable:     "تدفق البيانات القابل للوصول", // TRANSLATION_REVIEW_NEEDED
		FieldReferences:    "المراجع",                     // TRANSLATION_REVIEW_NEEDED
		FieldLocation:      "الموقع",                      // TRANSLATION_REVIEW_NEEDED
		ConfidenceLabel:    "ثقة",                         // TRANSLATION_REVIEW_NEEDED
		StatusBlocking:     "حاجب",                        // TRANSLATION_REVIEW_NEEDED
		StatusConfirmed:    "مؤكد",                        // TRANSLATION_REVIEW_NEEDED
		ScanStartedLabel:   "بدأ الفحص:",                  // TRANSLATION_REVIEW_NEEDED
		DurationLabel:      "المدة:",                      // TRANSLATION_REVIEW_NEEDED
		ModeLabel:          "الوضع:",                      // TRANSLATION_REVIEW_NEEDED
		EndpointsLabel:     "النقاط النهائية:",            // TRANSLATION_REVIEW_NEEDED
		TotalFindingsLabel: "إجمالي النتائج:",             // TRANSLATION_REVIEW_NEEDED
		NoFindingsMessage:  "لم يتم العثور على نتائج.",    // TRANSLATION_REVIEW_NEEDED

		CoverageTitle:                    "تغطية الماسحات",                                                                                       // TRANSLATION_REVIEW_NEEDED
		CoverageAnalyzer:                 "المحلل",                                                                                               // TRANSLATION_REVIEW_NEEDED
		CoverageClass:                    "الحالة",                                                                                               // TRANSLATION_REVIEW_NEEDED
		CoverageReason:                   "السبب",                                                                                                // TRANSLATION_REVIEW_NEEDED
		CoverageAttempts:                 "المحاولات",                                                                                            // TRANSLATION_REVIEW_NEEDED
		CoverageDetail:                   "التفاصيل",                                                                                             // TRANSLATION_REVIEW_NEEDED
		CoverageComplete:                 "التغطية كاملة",                                                                                        // TRANSLATION_REVIEW_NEEDED
		CoverageIncomplete:               "التغطية غير كاملة:",                                                                                   // TRANSLATION_REVIEW_NEEDED
		CoverageRequiredMissing:          "محللات مطلوبة لم تُنفَّذ:",                                                                            // TRANSLATION_REVIEW_NEEDED
		CoverageNotRecorded:              "لم تُسجَّل التغطية في هذه النسخة من المحرك",                                                           // TRANSLATION_REVIEW_NEEDED
		CoverageNotMeasured:              "لم تُقَس التغطية",                                                                                     // TRANSLATION_REVIEW_NEEDED
		VerdictPass:                      "ناجح",                                                                                                 // TRANSLATION_REVIEW_NEEDED
		VerdictWarn:                      "تحذير",                                                                                                // TRANSLATION_REVIEW_NEEDED
		VerdictBlocked:                   "محجوب",                                                                                                // TRANSLATION_REVIEW_NEEDED
		VerdictBlockedCoverageIncomplete: "محجوب — والتغطية غير كاملة أيضًا",                                                                     // TRANSLATION_REVIEW_NEEDED
		VerdictCoverageIncomplete:        "التغطية غير كاملة",                                                                                    // TRANSLATION_REVIEW_NEEDED
		ClassOK:                          "اشتغل", ClassNotApplicable: "غير قابل للتطبيق", ClassDisabled: "معطَّل", ClassUnavailable: "غير متاح", // TRANSLATION_REVIEW_NEEDED
		ClassUnsupported: "غير مدعوم", ClassFailed: "فشل", ClassUnknown: "غير معروف", // TRANSLATION_REVIEW_NEEDED
	}
}
