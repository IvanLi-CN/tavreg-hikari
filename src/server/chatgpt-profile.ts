export function profileFullName(rawName: string): string {
  const cleaned = String(rawName || "")
    .replace(/[^a-zA-Z\s'-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const parts = cleaned.split(" ").filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]} ${parts[1]}`.trim();
  }
  if (parts.length === 1) {
    return `${parts[0]} Hoshino`;
  }
  return "Mika Hoshino";
}

export function calculateAgeYears(birthDate: string): string {
  const [yearValue = Number.NaN, monthValue = Number.NaN, dayValue = Number.NaN] = birthDate
    .split("-")
    .map((value) => Number.parseInt(value, 10));
  if (!Number.isFinite(yearValue) || !Number.isFinite(monthValue) || !Number.isFinite(dayValue)) {
    return "30";
  }
  const today = new Date();
  let age = today.getUTCFullYear() - yearValue;
  const monthIndex = today.getUTCMonth() + 1;
  const dayOfMonth = today.getUTCDate();
  if (monthIndex < monthValue || (monthIndex === monthValue && dayOfMonth < dayValue)) {
    age -= 1;
  }
  return String(Math.max(18, Math.min(99, age)));
}

function buildBirthTokenGroups(birthDate: string): string[][] {
  const [year = "", month = "", day = ""] = birthDate.split("-");
  const monthNumber = Number(month);
  const monthNames = [
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];
  const monthName = monthNames[monthNumber] || month;
  return [
    [year],
    [day, String(Number(day))].filter(Boolean),
    [month, String(Number(month)), monthName, monthName.slice(0, 3)].filter(Boolean),
  ];
}

export function isBirthDateReadyFromVisibleValues(visibleBirthValues: string[], birthDate: string): boolean {
  const normalizedValues = visibleBirthValues
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  if (normalizedValues.length === 0) return false;
  const groups = buildBirthTokenGroups(birthDate);
  return groups.every((group) =>
    group.some((token) => {
      const normalizedToken = String(token || "").trim().toLowerCase();
      if (!normalizedToken) return false;
      return normalizedValues.some((value) => value === normalizedToken || value.includes(normalizedToken));
    }),
  );
}
