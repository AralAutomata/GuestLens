import type { PolicyProfile, PolicyProfileDefinition } from "@/lib/types";

export const DEFAULT_POLICY_PROFILE: PolicyProfile = "balanced";

export const POLICY_PROFILES: PolicyProfileDefinition[] = [
  {
    id: "balanced",
    label: "Balanced",
    description: "Prioritizes solid guest hardening without treating every integration surface as unacceptable.",
    emphasis: "General-purpose hardened Linux guest posture."
  },
  {
    id: "high-isolation",
    label: "High Isolation",
    description: "Raises the cost of guest-host integration surfaces and exposed services.",
    emphasis: "Compartmentalized workstations and operational VMs."
  },
  {
    id: "paranoid-lab",
    label: "Paranoid Lab",
    description: "Treats crossover surfaces and policy ambiguity as materially higher risk.",
    emphasis: "Research sandboxes and highly sensitive isolation workloads."
  }
];

export function isPolicyProfile(value: string): value is PolicyProfile {
  return POLICY_PROFILES.some((profile) => profile.id === value);
}

export function getPolicyProfileDefinition(profile: PolicyProfile): PolicyProfileDefinition {
  return POLICY_PROFILES.find((item) => item.id === profile) ?? POLICY_PROFILES[0];
}
