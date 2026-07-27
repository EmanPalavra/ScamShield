import { extractMlFeatures, ML_FEATURE_DIMENSION } from "./ml-features.ts";
import { mlModel } from "./ml-model.ts";

let decodedWeights: Int8Array | null = null;

function weights() {
  if (decodedWeights) return decodedWeights;
  if (!mlModel.weightsBase64) {
    decodedWeights = new Int8Array(ML_FEATURE_DIMENSION);
    return decodedWeights;
  }
  const binary = atob(mlModel.weightsBase64);
  const values = new Int8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    values[index] = binary.charCodeAt(index) - 128;
  }
  decodedWeights = values;
  return values;
}

function sigmoid(value: number) {
  if (value >= 0) return 1 / (1 + Math.exp(-value));
  const exp = Math.exp(value);
  return exp / (1 + exp);
}

export function predictLocalScamProbability(message: string) {
  if (!mlModel.weightsBase64) return 0;
  const modelWeights = weights();
  let logit = mlModel.bias;
  for (const [index, value] of extractMlFeatures(message)) {
    logit += modelWeights[index] * mlModel.weightScale * value;
  }
  return sigmoid(logit);
}

export function hybridizeRuleScore(
  ruleScore: number,
  mlProbability: number,
  suppressMlRaise = false,
) {
  if (
    !mlModel.weightsBase64
    || ruleScore >= 34
    || suppressMlRaise
    || mlProbability < mlModel.decisionThreshold
  ) {
    return ruleScore;
  }

  // ML may recover scams missed by rules, but it cannot downgrade a rule alert or
  // turn an existing Medium result into High. This keeps the hybrid predictable.
  const confidenceAboveThreshold = (mlProbability - mlModel.decisionThreshold)
    / Math.max(0.001, 1 - mlModel.decisionThreshold);
  return Math.min(66, Math.round(34 + confidenceAboveThreshold * 32));
}
