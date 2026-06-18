import type { Rule } from "../types.js";

export const FILE_SYSTEM_RULES: readonly Rule[] = [
  {
    id: "FS-001",
    category: "filesystem-abuse",
    severity: "HIGH",
    pattern: /\brm\s+-[rf]{1,2}\s+(\/|\~\/|\$HOME\/|\/etc\/|\/usr\/|\/home\/)/i,
    message: "Filesystem abuse: recursive delete targeting system or home directories",
  },
  {
    id: "FS-002",
    category: "filesystem-abuse",
    severity: "HIGH",
    pattern: /\bdd\b[^#\n]*\bof=\s*(\/dev\/|\/boot\/|\/etc\/)/i,
    message: "Filesystem abuse: dd writing to device/boot/system path",
  },
  {
    id: "FS-003",
    category: "filesystem-abuse",
    severity: "MEDIUM",
    pattern: /\bwrite\b[^#\n]*(\/etc\/hosts|\/etc\/resolv\.conf|\/etc\/passwd)/i,
    message: "Filesystem abuse: writing to sensitive system config files",
  },
];
