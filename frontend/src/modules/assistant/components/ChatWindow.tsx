import { useEffect, useRef, useState } from "react";

import SendRoundedIcon from "@mui/icons-material/SendRounded";

import {
  Box,
  Button,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";

import MessageBubble from "./MessageBubble";
import PromptSuggestions from "./PromptSuggestions";
import assistantService from "../services/assistantService";
import type { ChatMessage } from "../types/assistant";

function ChatWindow() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    assistantService.getMessages().then((initial) => {
      setMessages(initial);
    });
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isTyping]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text) return;

    const userMessage: ChatMessage = {
      id: Date.now(),
      sender: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsTyping(true);

    try {
      const reply = await assistantService.ask(text);
      const assistantMessage: ChatMessage = {
        id: Date.now() + 1,
        sender: "assistant",
        content: reply,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch {
      const errorMessage: ChatMessage = {
        id: Date.now() + 1,
        sender: "assistant",
        content: "I couldn't process that request. Please try again.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <Paper
      elevation={0}
      sx={{
        p: 3,
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        height: "100%",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <Stack spacing={3} height="100%">
        <PromptSuggestions />

        <Stack
          spacing={2}
          flex={1}
          sx={{
            overflowY: "auto",
            minHeight: 450,
          }}
        >
          {messages.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
            />
          ))}
          {isTyping && (
            <Box sx={{ px: 2, py: 1 }}>
              <Typography variant="body2" color="text.secondary">
                Assistant is thinking...
              </Typography>
            </Box>
          )}
          <div ref={bottomRef} />
        </Stack>

        <Stack
          direction="row"
          spacing={2}
        >
          <TextField
            fullWidth
            placeholder="Ask about threats, incidents, SIEM events, reports..."
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void handleSend();
              }
            }}
          />
          <Button
            variant="contained"
            endIcon={<SendRoundedIcon />}
            onClick={handleSend}
            disabled={!input.trim() || isTyping}
          >
            Send
          </Button>
        </Stack>
      </Stack>
    </Paper>
  );
}

export default ChatWindow;
