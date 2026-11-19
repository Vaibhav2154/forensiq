const convertUSToIST = (usTimeString: string, usTimeZone: string = "America/New_York") => {
  // Parse US time in the correct timezone
  const date = new Date(
    new Date(usTimeString).toLocaleString("en-US", { timeZone: usTimeZone })
  );

  // Convert to IST string
  return date.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    hour12: true,
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
  });
};
