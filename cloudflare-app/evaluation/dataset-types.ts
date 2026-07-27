export type DatasetLabel = "scam" | "legitimate";
export type AnnotationStatus =
  | "authority-confirmed"
  | "authority-described"
  | "expert-reviewed"
  | "public-corpus-label"
  | "user-reported";
export type EvaluationSplit = "calibration" | "holdout";
export type EvidenceKind = "verbatim-redacted" | "authority-described" | "corpus-record";

export interface EvaluationSample {
  id: string;
  label: DatasetLabel;
  language: string;
  scamType: string | null;
  text: string;
  source: string;
  sourceUrl: string | null;
  annotationStatus: AnnotationStatus;
  evaluationSplit?: EvaluationSplit;
  evidenceKind?: EvidenceKind;
}

export interface ScoredSample extends EvaluationSample {
  score: number;
  predictedScamType: string;
  detectedLanguage: string;
}
