import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Switch,
  FormControlLabel,
  Button,
  Divider,
  Card,
  CardContent,
  Alert,
  Snackbar,
} from '@mui/material';
import Grid2 from '@mui/material/Grid';

interface NotificationSettings {
  email: {
    enabled: boolean;
    recipients: string;
    minPriority: string;
  };
  slack: {
    enabled: boolean;
    webhook: string;
    channel: string;
  };
}

interface EnrichmentSettings {
  geoip: {
    enabled: boolean;
    updateInterval: number;
  };
  threatIntel: {
    enabled: boolean;
    updateInterval: number;
    apiKey: string;
  };
}

interface RetentionSettings {
  alertRetentionDays: number;
  logsRetentionDays: number;
}

interface CorrelationSettings {
  timeWindow: number;
  minSimilarity: number;
}

interface Settings {
  notifications: NotificationSettings;
  enrichment: EnrichmentSettings;
  retention: RetentionSettings;
  correlation: CorrelationSettings;
}

// Mock settings - will be replaced with real API data
const defaultSettings: Settings = {
  notifications: {
    email: {
      enabled: true,
      recipients: 'security@example.com',
      minPriority: 'HIGH',
    },
    slack: {
      enabled: true,
      webhook: 'https://hooks.slack.com/services/xxx/yyy/zzz',
      channel: '#security-alerts',
    },
  },
  enrichment: {
    geoip: {
      enabled: true,
      updateInterval: 24,
    },
    threatIntel: {
      enabled: true,
      updateInterval: 12,
      apiKey: '********',
    },
  },
  retention: {
    alertRetentionDays: 90,
    logsRetentionDays: 30,
  },
  correlation: {
    timeWindow: 60,
    minSimilarity: 0.7,
  },
};

export default function Settings() {
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as const });

  const handleSave = () => {
    // In a real implementation, this would save to the backend
    setSnackbar({
      open: true,
      message: 'Settings saved successfully',
      severity: 'success',
    });
  };

  const handleChange = <
    S extends keyof Settings,
    K extends keyof Settings[S],
    F extends keyof Settings[S][K]
  >(
    section: S,
    subsection: K,
    field: F,
    value: Settings[S][K][F]
  ) => {
    setSettings((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [subsection]: {
          ...prev[section][subsection],
          [field]: value,
        },
      },
    }));
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom>
        System Settings
      </Typography>

      <Grid2 container spacing={3}>
        {/* Notification Settings */}
        <Grid2 item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Notification Settings
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                Email Notifications
              </Typography>
              <Box sx={{ ml: 2, mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.notifications.email.enabled}
                      onChange={(e) =>
                        handleChange('notifications', 'email', 'enabled', e.target.checked)
                      }
                    />
                  }
                  label="Enable Email Notifications"
                />
                <TextField
                  fullWidth
                  label="Recipients"
                  value={settings.notifications.email.recipients}
                  onChange={(e) =>
                    handleChange('notifications', 'email', 'recipients', e.target.value)
                  }
                  margin="normal"
                  size="small"
                />
                <TextField
                  fullWidth
                  label="Minimum Priority"
                  value={settings.notifications.email.minPriority}
                  onChange={(e) =>
                    handleChange('notifications', 'email', 'minPriority', e.target.value)
                  }
                  margin="normal"
                  size="small"
                  select
                  SelectProps={{ native: true }}
                >
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </TextField>
              </Box>

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Slack Notifications
              </Typography>
              <Box sx={{ ml: 2 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.notifications.slack.enabled}
                      onChange={(e) =>
                        handleChange('notifications', 'slack', 'enabled', e.target.checked)
                      }
                    />
                  }
                  label="Enable Slack Notifications"
                />
                <TextField
                  fullWidth
                  label="Webhook URL"
                  value={settings.notifications.slack.webhook}
                  onChange={(e) =>
                    handleChange('notifications', 'slack', 'webhook', e.target.value)
                  }
                  margin="normal"
                  size="small"
                  type="password"
                />
                <TextField
                  fullWidth
                  label="Channel"
                  value={settings.notifications.slack.channel}
                  onChange={(e) =>
                    handleChange('notifications', 'slack', 'channel', e.target.value)
                  }
                  margin="normal"
                  size="small"
                />
              </Box>
            </CardContent>
          </Card>
        </Grid2>

        {/* Enrichment Settings */}
        <Grid2 item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Enrichment Settings
              </Typography>

              <Typography variant="subtitle2" gutterBottom>
                GeoIP Database
              </Typography>
              <Box sx={{ ml: 2, mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.enrichment.geoip.enabled}
                      onChange={(e) =>
                        handleChange('enrichment', 'geoip', 'enabled', e.target.checked)
                      }
                    />
                  }
                  label="Enable GeoIP Enrichment"
                />
                <TextField
                  fullWidth
                  label="Update Interval (hours)"
                  value={settings.enrichment.geoip.updateInterval}
                  onChange={(e) =>
                    handleChange('enrichment', 'geoip', 'updateInterval', parseInt(e.target.value))
                  }
                  margin="normal"
                  size="small"
                  type="number"
                />
              </Box>

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Threat Intelligence
              </Typography>
              <Box sx={{ ml: 2 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.enrichment.threatIntel.enabled}
                      onChange={(e) =>
                        handleChange('enrichment', 'threatIntel', 'enabled', e.target.checked)
                      }
                    />
                  }
                  label="Enable Threat Intelligence"
                />
                <TextField
                  fullWidth
                  label="API Key"
                  value={settings.enrichment.threatIntel.apiKey}
                  onChange={(e) =>
                    handleChange('enrichment', 'threatIntel', 'apiKey', e.target.value)
                  }
                  margin="normal"
                  size="small"
                  type="password"
                />
                <TextField
                  fullWidth
                  label="Update Interval (hours)"
                  value={settings.enrichment.threatIntel.updateInterval}
                  onChange={(e) =>
                    handleChange(
                      'enrichment',
                      'threatIntel',
                      'updateInterval',
                      parseInt(e.target.value)
                    )
                  }
                  margin="normal"
                  size="small"
                  type="number"
                />
              </Box>
            </CardContent>
          </Card>
        </Grid2>

        {/* System Settings */}
        <Grid2 item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Settings
              </Typography>

              <Grid2 container spacing={3}>
                <Grid2 item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Data Retention
                  </Typography>
                  <Box sx={{ ml: 2 }}>
                    <TextField
                      fullWidth
                      label="Alert Retention (days)"
                      value={settings.retention.alertRetentionDays}
                      onChange={(e) =>
                        setSettings((prev) => ({
                          ...prev,
                          retention: {
                            ...prev.retention,
                            alertRetentionDays: parseInt(e.target.value),
                          },
                        }))
                      }
                      margin="normal"
                      size="small"
                      type="number"
                    />
                    <TextField
                      fullWidth
                      label="Log Retention (days)"
                      value={settings.retention.logsRetentionDays}
                      onChange={(e) =>
                        setSettings((prev) => ({
                          ...prev,
                          retention: {
                            ...prev.retention,
                            logsRetentionDays: parseInt(e.target.value),
                          },
                        }))
                      }
                      margin="normal"
                      size="small"
                      type="number"
                    />
                  </Box>
                </Grid2>

                <Grid2 item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Correlation Settings
                  </Typography>
                  <Box sx={{ ml: 2 }}>
                    <TextField
                      fullWidth
                      label="Time Window (minutes)"
                      value={settings.correlation.timeWindow}
                      onChange={(e) =>
                        setSettings((prev) => ({
                          ...prev,
                          correlation: {
                            ...prev.correlation,
                            timeWindow: parseInt(e.target.value),
                          },
                        }))
                      }
                      margin="normal"
                      size="small"
                      type="number"
                    />
                    <TextField
                      fullWidth
                      label="Minimum Similarity (0-1)"
                      value={settings.correlation.minSimilarity}
                      onChange={(e) =>
                        setSettings((prev) => ({
                          ...prev,
                          correlation: {
                            ...prev.correlation,
                            minSimilarity: parseFloat(e.target.value),
                          },
                        }))
                      }
                      margin="normal"
                      size="small"
                      type="number"
                      inputProps={{ step: 0.1, min: 0, max: 1 }}
                    />
                  </Box>
                </Grid2>
              </Grid2>
            </CardContent>
          </Card>
        </Grid2>
      </Grid2>

      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          variant="contained"
          color="primary"
          onClick={handleSave}
          size="large"
        >
          Save Settings
        </Button>
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
} 