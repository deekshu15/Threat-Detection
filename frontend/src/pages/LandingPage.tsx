import { useEffect, useMemo, useState } from "react";
import ArrowForwardRoundedIcon from "@mui/icons-material/ArrowForwardRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import EmailRoundedIcon from "@mui/icons-material/EmailRounded";
import GitHubIcon from "@mui/icons-material/GitHub";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import LinkedInIcon from "@mui/icons-material/LinkedIn";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";
import NotificationsActiveRoundedIcon from "@mui/icons-material/NotificationsActiveRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import SummarizeRoundedIcon from "@mui/icons-material/SummarizeRounded";
import InsightsRoundedIcon from "@mui/icons-material/InsightsRounded";
import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";
import XIcon from "@mui/icons-material/X";
import { Box, Button, Collapse, Container, Grid, IconButton, Link, Stack, TextField, Typography, useTheme } from "@mui/material";
import { useNavigate } from "react-router-dom";
import { SiGitbook } from "react-icons/si";

import GlassSurface from "../components/ui/GlassSurface";

const features = [
  {
    title: "Operational clarity",
    description: "Turn scattered telemetry into a calm, guided view of the threats that matter most.",
    icon: InsightsRoundedIcon,
  },
  {
    title: "Focused intelligence",
    description: "Layer context, detections, and responses into one premium workflow for analysts.",
    icon: AutoAwesomeRoundedIcon,
  },
  {
    title: "Trusted protections",
    description: "Keep teams aligned with streamlined review paths and evidence-backed actions.",
    icon: SecurityRoundedIcon,
  },
  {
    title: "Real-time alerting",
    description: "Get instant, prioritized notifications the moment a credible threat is detected.",
    icon: NotificationsActiveRoundedIcon,
  },
  {
    title: "Team collaboration",
    description: "Assign, comment, and hand off cases seamlessly across shifts and analysts.",
    icon: GroupsRoundedIcon,
  },
  {
    title: "Actionable reporting",
    description: "Auto-generated, exportable summaries for leadership and compliance reviews.",
    icon: SummarizeRoundedIcon,
  },
];

const aboutStats = [
  { label: "Teams protected", value: "500+" },
  { label: "Uptime", value: "99.9%" },
  { label: "24/7 monitoring", value: "Always on" },
  { label: "Avg. response", value: "10 min" },
];

const footerGroups = [
  {
    title: "Product",
    links: [
      { label: "Features", href: "#features" },
      { label: "Pricing", href: "#feedback" },
      { label: "Security", href: "#about" },
      { label: "Changelog", href: "#feedback" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "#about" },
      { label: "Careers", href: "#feedback" },
      { label: "Blog", href: "#features" },
      { label: "Contact", href: "#feedback" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Docs", href: "#features" },
      { label: "Support", href: "#feedback" },
      { label: "Feedback", href: "#feedback" },
      { label: "Status", href: "#about" },
    ],
  },
];

function LandingPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [revealed, setRevealed] = useState({ features: false, about: false, feedback: false });

  const navItems = useMemo(
    () => [
      { label: "Features", href: "#features" },
      { label: "About", href: "#about" },
      { label: "Feedback", href: "#feedback" },
    ],
    []
  );

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setMenuOpen(false);
  };

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    handleScroll();
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  useEffect(() => {
    const sections = [document.getElementById("features"), document.getElementById("about"), document.getElementById("feedback")];
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const id = entry.target.id as keyof typeof revealed;
            setRevealed((current) => ({ ...current, [id]: true }));
          }
        });
      },
      { threshold: 0.16 }
    );

    sections.forEach((section) => section && observer.observe(section));
    return () => observer.disconnect();
  }, []);

  const navAction = (href: string) => {
    if (href.startsWith("#")) {
      scrollToSection(href.slice(1));
      return;
    }
    navigate(href);
    setMenuOpen(false);
  };

  return (
    <Box sx={{ minHeight: "100vh", color: "text.primary", position: "relative", overflow: "hidden" }}>
      <Box
        sx={{
          position: "fixed",
          inset: 0,
          pointerEvents: "none",
          background: theme.palette.mode === "dark"
            ? "radial-gradient(circle at 18% 18%, rgba(79, 93, 255, 0.20), transparent 28%), radial-gradient(circle at 82% 14%, rgba(46, 158, 142, 0.14), transparent 24%), radial-gradient(circle at 50% 86%, rgba(79, 93, 255, 0.10), transparent 26%)"
            : "radial-gradient(circle at 18% 18%, rgba(79, 93, 255, 0.12), transparent 28%), radial-gradient(circle at 82% 14%, rgba(46, 158, 142, 0.10), transparent 24%), radial-gradient(circle at 50% 86%, rgba(79, 93, 255, 0.08), transparent 26%)",
          opacity: 0.95,
        }}
      />

      <Box component="header" sx={{ position: "sticky", top: 0, zIndex: 1300, px: { xs: 1.5, md: 3 }, pt: { xs: 1.5, md: 2 }, pb: 1.5 }}>
        <Container maxWidth="xl">
          <GlassSurface
            sx={{
              px: { xs: 2, md: 3 },
              py: scrolled ? { xs: 1.25, md: 1.35 } : { xs: 1.5, md: 1.6 },
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 2.5,
              transform: scrolled ? "translateY(-1px) scale(0.99)" : "translateY(0) scale(1)",
              transition: "all 200ms ease",
              backdropFilter: scrolled ? "blur(24px)" : "blur(16px)",
              boxShadow: scrolled ? "0 24px 56px rgba(2, 6, 23, 0.38)" : "0 16px 36px rgba(2, 6, 23, 0.28)",
            }}
          >
            <Button
              onClick={() => navigate("/")}
              sx={{
                p: 0,
                minWidth: 0,
                display: "flex",
                alignItems: "center",
                gap: 1.4,
                color: "inherit",
                textAlign: "left",
                "&:hover": { backgroundColor: "transparent" },
              }}
            >
              <Box sx={{ width: 44, height: 44, borderRadius: "50%", bgcolor: "primary.main", display: "flex", alignItems: "center", justifyContent: "center", color: "#F5F6F8", boxShadow: "0 14px 32px rgba(79,93,255,0.30)" }}>
                <ShieldRoundedIcon />
              </Box>
              <Box sx={{ display: { xs: "none", sm: "block" } }}>
                <Typography sx={{ fontWeight: 800, lineHeight: 1.1 }}>Northstar Security</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                  Focused defense for modern security teams
                </Typography>
              </Box>
            </Button>

            <Stack direction="row" spacing={2.5} alignItems="center" sx={{ display: { xs: "none", md: "flex" }, flex: 1, justifyContent: "center" }}>
              {navItems.map((item) => (
                <Button
                  key={item.label}
                  onClick={() => navAction(item.href)}
                  variant="text"
                  sx={{ color: "text.secondary", px: 1.2, minWidth: 0, "&:hover": { color: "primary.main", backgroundColor: "transparent" } }}
                >
                  {item.label}
                </Button>
              ))}
            </Stack>

            <Stack direction="row" spacing={1.1} alignItems="center" sx={{ flexShrink: 0 }}>
              <Button variant="outlined" color="primary" onClick={() => navigate("/sign-in")} sx={{ display: { xs: "none", sm: "inline-flex" } }}>
                Sign In
              </Button>
              <Button variant="contained" color="primary" onClick={() => navigate("/sign-up")} sx={{ display: { xs: "none", sm: "inline-flex" } }}>
                Sign Up
              </Button>
              <IconButton
                onClick={() => setMenuOpen((value) => !value)}
                sx={{ display: { xs: "inline-flex", md: "none" }, color: "text.primary" }}
                aria-label="Open menu"
              >
                {menuOpen ? <CloseRoundedIcon /> : <MenuRoundedIcon />}
              </IconButton>
            </Stack>
          </GlassSurface>

          <Collapse in={menuOpen} timeout={180} unmountOnExit>
            <GlassSurface sx={{ mt: 1.2, p: 2.2, display: { xs: "flex", md: "none" }, flexDirection: "column", gap: 1.3 }}>
              {navItems.map((item) => (
                <Button key={item.label} onClick={() => navAction(item.href)} variant="text" sx={{ justifyContent: "flex-start", color: "text.secondary" }}>
                  {item.label}
                </Button>
              ))}
              <Stack direction="row" spacing={1.2}>
                <Button fullWidth variant="outlined" color="primary" onClick={() => navigate("/sign-in")}>
                  Sign In
                </Button>
                <Button fullWidth variant="contained" color="primary" onClick={() => navigate("/sign-up")}>
                  Sign Up
                </Button>
              </Stack>
            </GlassSurface>
          </Collapse>
        </Container>
      </Box>

      <Box component="main" sx={{ position: "relative", zIndex: 1 }}>
        <Box sx={{ pt: { xs: 6.5, md: 8.5 }, pb: { xs: 6, md: 8.5 } }}>
          <Container maxWidth="lg">
            <Stack alignItems="center" textAlign="center" spacing={2.6} sx={{ position: "relative" }}>
              <Box sx={{ position: "absolute", inset: { xs: -16, md: -40 }, filter: "blur(36px)", opacity: 0.8, pointerEvents: "none" }}>
                <Box sx={{ position: "absolute", top: "8%", left: "50%", transform: "translateX(-50%)", width: { xs: 220, md: 360 }, height: { xs: 220, md: 360 }, borderRadius: "50%", bgcolor: "rgba(79,93,255,0.16)" }} />
                <Box sx={{ position: "absolute", top: "24%", right: { xs: "2%", md: "12%" }, width: { xs: 140, md: 220 }, height: { xs: 140, md: 220 }, borderRadius: "50%", bgcolor: "rgba(46,158,142,0.12)" }} />
              </Box>

              <Box sx={{ position: "relative", zIndex: 1, maxWidth: 860, mx: "auto" }}>
                <Box sx={{ display: "inline-flex", alignItems: "center", gap: 1, px: 1.55, py: 0.75, mb: 2, borderRadius: 999, bgcolor: "rgba(79,93,255,0.14)", border: "1px solid rgba(255,255,255,0.12)", color: "primary.light" }}>
                  <AutoAwesomeRoundedIcon fontSize="small" />
                  <Typography variant="body2" fontWeight={700} sx={{ fontSize: "0.9rem" }}>
                    Premium intelligence for modern teams
                  </Typography>
                </Box>

                <Typography
                  variant="h1"
                  sx={{
                    fontSize: { xs: "2.1rem", sm: "2.7rem", md: "3.35rem", lg: "4rem" },
                    lineHeight: 1.08,
                    fontWeight: 800,
                    letterSpacing: "-0.035em",
                    maxWidth: 820,
                    mx: "auto",
                  }}
                >
                  Calm, confident defense for every alert that matters.
                </Typography>

                <Typography variant="h6" sx={{ mt: 1.8, mx: "auto", maxWidth: 640, color: "text.secondary", lineHeight: 1.65, fontSize: { xs: "0.95rem", md: "1.02rem" } }}>
                  Northstar Security gives leaders one polished workspace to align detection, response, and continuity without the clutter of a fragmented toolchain.
                </Typography>
              </Box>

              <GlassSurface sx={{ position: "relative", zIndex: 1, maxWidth: 700, width: "100%", p: { xs: 2.2, md: 3 }, textAlign: "center" }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "center", gap: 2 }}>
                  <Typography sx={{ fontSize: { xs: 38, md: 52 }, lineHeight: 1, color: "primary.light", fontWeight: 800, mt: -0.15 }}>
                    “
                  </Typography>
                  <Box sx={{ maxWidth: 560 }}>
                    <Typography
                      variant="h5"
                      sx={{
                        fontStyle: "italic",
                        lineHeight: 1.7,
                        color: "text.primary",
                        fontSize: { xs: "1.02rem", md: "1.2rem" },
                      }}
                    >
                      Northstar gave our SOC the clarity we had been missing for years.
                    </Typography>
                    <Typography variant="body2" sx={{ mt: 1.4, color: "text.secondary" }}>
                      Maya Chen, Security Director at a Fortune 500 financial firm
                    </Typography>
                  </Box>
                </Box>
              </GlassSurface>

              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.4} sx={{ position: "relative", zIndex: 1, pt: 0.5 }}>
                <Button variant="contained" color="primary" size="medium" endIcon={<ArrowForwardRoundedIcon />} onClick={() => navigate("/sign-in")}>
                  Sign In / Sign Up
                </Button>
                <Button variant="outlined" color="primary" size="medium" onClick={() => scrollToSection("features")}>
                  Explore Features
                </Button>
              </Stack>
            </Stack>
          </Container>
        </Box>

        <Box
          id="features"
          sx={{
            scrollMarginTop: { xs: 108, md: 124 },
            py: { xs: 6, md: 8.5 },
            opacity: revealed.features ? 1 : 0,
            transform: revealed.features ? "translateY(0) scale(1)" : "translateY(22px) scale(0.985)",
            transition: "opacity 260ms ease, transform 320ms ease",
          }}
        >
          <Container maxWidth="xl">
            <Stack spacing={1.2} sx={{ mb: 3.5, maxWidth: 920, mx: "auto", alignItems: "center", textAlign: "center" }}>
              <Typography variant="overline" sx={{ color: "primary.light", fontWeight: 800, letterSpacing: "0.14em" }}>
                FEATURES
              </Typography>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                    fontSize: { xs: "1.8rem", md: "2.35rem" },
                    whiteSpace: { xs: "normal", md: "nowrap" },
                  maxWidth: "none",
                }}
              >
                Crafted for calm, confident operations.
              </Typography>
            </Stack>

            <Grid container spacing={3}>
              {features.map((feature, index) => {
                const Icon = feature.icon;
                const isVisible = revealed.features;

                return (
                  <Grid key={feature.title} size={{ xs: 12, md: 6, lg: 4 }}>
                    <GlassSurface
                      sx={{
                        p: 3,
                        height: "100%",
                        transition: "transform 200ms ease, box-shadow 200ms ease, border-color 200ms ease, opacity 220ms ease",
                        opacity: isVisible ? 1 : 0,
                        transform: isVisible ? "translateY(0) scale(1)" : "translateY(26px) scale(0.94)",
                        transitionDelay: `${index * 70}ms`,
                        "&:hover": {
                          transform: "translateY(-6px) scale(1.01)",
                          boxShadow: "0 28px 52px rgba(2, 6, 23, 0.34)",
                        },
                      }}
                    >
                      <Box sx={{ width: 48, height: 48, borderRadius: 3, bgcolor: "rgba(79,93,255,0.14)", border: "1px solid rgba(255,255,255,0.12)", display: "flex", alignItems: "center", justifyContent: "center", mb: 2.2 }}>
                        <Icon sx={{ color: "primary.light" }} />
                      </Box>
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                        {feature.title}
                      </Typography>
                      <Typography sx={{ color: "text.secondary", lineHeight: 1.7 }}>
                        {feature.description}
                      </Typography>
                    </GlassSurface>
                  </Grid>
                );
              })}
            </Grid>
          </Container>
        </Box>

        <Box id="about" sx={{ scrollMarginTop: { xs: 108, md: 124 }, py: { xs: 6, md: 8.5 }, opacity: revealed.about ? 1 : 0, transform: revealed.about ? "translateY(0)" : "translateY(18px)", transition: "opacity 260ms ease, transform 320ms ease" }}>
          <Container maxWidth="xl">
            <Stack spacing={1.2} sx={{ mb: 3.5, maxWidth: 760, mx: "auto", textAlign: "center", alignItems: "center" }}>
              <Typography variant="overline" sx={{ color: "primary.light", fontWeight: 800, letterSpacing: "0.14em" }}>
                ABOUT US
              </Typography>
              <Typography variant="h3" sx={{ fontWeight: 800, fontSize: { xs: "1.8rem", md: "2.35rem" } }}>
                Built by security practitioners, for security practitioners.
              </Typography>
            </Stack>

            <Box sx={{ width: "100%", maxWidth: 960, mx: "auto" }}>
              <GlassSurface sx={{ p: { xs: 3, md: 4 }, width: "100%" }}>
                  <Stack spacing={2.2} sx={{ color: "text.secondary", lineHeight: 1.8, textAlign: "center", alignItems: "center" }}>
                    <Typography>
                      Northstar was built to remove the friction that slows modern teams down: fragmented telemetry, noisy alerts, and disconnected handoffs between analysts and leadership.
                    </Typography>
                    <Typography>
                      The platform brings detection, investigation, and reporting into one calm operating layer so teams can focus on outcomes instead of juggling tools.
                    </Typography>
                    <Typography>
                      The result is faster triage, stronger confidence, and a more reliable security posture for every organization we support.
                    </Typography>
                  </Stack>

                  <Grid container spacing={2} sx={{ mt: 3, justifyContent: "center" }}>
                    {aboutStats.map((stat) => (
                      <Grid key={stat.label} size={{ xs: 12, sm: 6, md: 3 }}>
                        <GlassSurface sx={{ p: 2.2, textAlign: "center", height: "100%", background: "rgba(255,255,255,0.05)" }}>
                          <Typography variant="h6" sx={{ fontWeight: 800 }}>
                            {stat.value}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>
                            {stat.label}
                          </Typography>
                        </GlassSurface>
                      </Grid>
                    ))}
                  </Grid>
              </GlassSurface>
            </Box>
          </Container>
        </Box>

        <Box id="feedback" sx={{ scrollMarginTop: { xs: 108, md: 124 }, py: { xs: 7, md: 10 }, opacity: revealed.feedback ? 1 : 0, transform: revealed.feedback ? "translateY(0)" : "translateY(18px)", transition: "opacity 260ms ease, transform 320ms ease" }}>
          <Container maxWidth="lg">
            <GlassSurface sx={{ p: { xs: 3, md: 4.2 }, maxWidth: 860, mx: "auto" }}>
              <Stack spacing={1.2} sx={{ mb: 2.5 }}>
                <Typography variant="overline" sx={{ color: "primary.light", fontWeight: 800, letterSpacing: "0.14em" }}>
                  FEEDBACK
                </Typography>
                <Typography variant="h3" sx={{ fontWeight: 800, fontSize: { xs: "2rem", md: "2.8rem" } }}>
                  We&apos;d love to hear from you.
                </Typography>
                <Typography sx={{ color: "text.secondary", maxWidth: 620, lineHeight: 1.75 }}>
                  Share your priorities and we&apos;ll follow up within one business day.
                </Typography>
              </Stack>

              <Grid container spacing={2.2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField label="Name" fullWidth />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField label="Email" fullWidth />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField label="Message" multiline minRows={5} fullWidth />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <Button variant="contained" color="primary" size="large" startIcon={<EmailRoundedIcon />} sx={{ width: "fit-content" }}>
                    Submit feedback
                  </Button>
                </Grid>
              </Grid>
            </GlassSurface>
          </Container>
        </Box>
      </Box>

      <Box component="footer" sx={{ mt: 4, px: { xs: 2, md: 4 }, pb: 3, position: "relative", zIndex: 1 }}>
        <Container maxWidth="xl">
          <Box
            sx={{
              borderTop: "1px solid rgba(255,255,255,0.12)",
              background: theme.palette.mode === "dark"
                ? "linear-gradient(180deg, rgba(16,21,28,0.72), rgba(11,15,20,0.94))"
                : "linear-gradient(180deg, rgba(255,255,255,0.72), rgba(245,247,255,0.92))",
              backdropFilter: "blur(18px)",
              WebkitBackdropFilter: "blur(18px)",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,0.10)",
              boxShadow: theme.palette.mode === "dark" ? "0 24px 56px rgba(2, 6, 23, 0.32)" : "0 24px 56px rgba(15, 23, 42, 0.12)",
              p: { xs: 3, md: 4 },
            }}
          >
            <Grid container spacing={4}>
              <Grid size={{ xs: 12, md: 4 }}>
                <Stack spacing={1.5}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.4 }}>
                    <Box sx={{ width: 42, height: 42, borderRadius: "50%", bgcolor: "primary.main", display: "flex", alignItems: "center", justifyContent: "center", color: "#F5F6F8" }}>
                      <ShieldRoundedIcon />
                    </Box>
                    <Box>
                      <Typography sx={{ fontWeight: 800 }}>Northstar Security</Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        Focused defense for modern security teams
                      </Typography>
                    </Box>
                  </Box>

                  <Typography sx={{ color: "text.secondary", maxWidth: 320, lineHeight: 1.75 }}>
                    One calm workspace for security leaders, analysts, and response teams.
                  </Typography>

                  <Stack direction="row" spacing={1.1}>
                    <IconButton color="primary" aria-label="LinkedIn">
                      <LinkedInIcon />
                    </IconButton>
                    <IconButton color="primary" aria-label="X">
                      <XIcon />
                    </IconButton>
                    <IconButton color="primary" aria-label="GitHub">
                      <GitHubIcon />
                    </IconButton>
                    <IconButton color="primary" aria-label="Docs">
                      <SiGitbook size={20} />
                    </IconButton>
                  </Stack>
                </Stack>
              </Grid>

              {footerGroups.map((group) => (
                <Grid key={group.title} size={{ xs: 12, sm: 4, md: 2 }}>
                  <Stack spacing={1.4}>
                    <Typography sx={{ fontWeight: 800 }}>{group.title}</Typography>
                    <Stack spacing={1.1}>
                      {group.links.map((link) => (
                        <Link key={link.label} href={link.href} underline="none" color="text.secondary" sx={{ width: "fit-content", transition: "color 160ms ease", "&:hover": { color: "primary.main" } }}>
                          {link.label}
                        </Link>
                      ))}
                    </Stack>
                  </Stack>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ mt: 4, pt: 2.5, borderTop: "1px solid rgba(255,255,255,0.10)", display: "flex", flexDirection: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { xs: "flex-start", sm: "center" }, gap: 1.5 }}>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                © 2026 Northstar Security. All rights reserved.
              </Typography>
              <Stack direction="row" spacing={2}>
                <Link href="#" underline="none" color="text.secondary">Privacy Policy</Link>
                <Link href="#" underline="none" color="text.secondary">Terms of Service</Link>
              </Stack>
            </Box>
          </Box>
        </Container>
      </Box>
    </Box>
  );
}

export default LandingPage;
