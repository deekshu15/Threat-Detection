import KeyboardArrowDownRoundedIcon from "@mui/icons-material/KeyboardArrowDownRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import PersonRoundedIcon from "@mui/icons-material/PersonRounded";
import SettingsRoundedIcon from "@mui/icons-material/SettingsRounded";

import {
  Avatar,
  Divider,
  ListItemIcon,
  Menu,
  MenuItem,
  Stack,
  Typography,
} from "@mui/material";
import { MouseEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import { authService } from "../auth/authService";

function UserMenu() {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const navigate = useNavigate();

  const open = Boolean(anchorEl);

  const handleOpen = (event: MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => setAnchorEl(null);

  const handleNavigate = (path: string) => {
    handleClose();
    navigate(path);
  };

  const handleLogout = async () => {
    handleClose();

    try {
      await authService.logout();
    } finally {
      // Remove only app session data; Amplify clears its own authentication tokens.
      window.sessionStorage.clear();
      navigate("/sign-in", { replace: true });
    }
  };

  return (
    <>
      <Stack
        direction="row"
        spacing={1}
        alignItems="center"
        sx={{
          cursor: "pointer",
        }}
        onClick={handleOpen}
      >
        <Avatar
          sx={{
            bgcolor: "primary.main",
            width: 40,
            height: 40,
          }}
        >
          A
        </Avatar>

        <Stack spacing={0}>
          <Typography fontWeight={600}>
            Administrator
          </Typography>

          <Typography
            variant="caption"
            color="text.secondary"
          >
            Security Analyst
          </Typography>
        </Stack>

        <KeyboardArrowDownRoundedIcon />
      </Stack>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
      >
        <MenuItem onClick={() => handleNavigate("/profile")}>
          <ListItemIcon>
            <PersonRoundedIcon fontSize="small" />
          </ListItemIcon>

          Profile
        </MenuItem>

        <MenuItem onClick={() => handleNavigate("/settings")}>
          <ListItemIcon>
            <SettingsRoundedIcon fontSize="small" />
          </ListItemIcon>

          Settings
        </MenuItem>

        <Divider />

        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <LogoutRoundedIcon fontSize="small" />
          </ListItemIcon>

          Logout
        </MenuItem>
      </Menu>
    </>
  );
}

export default UserMenu;
