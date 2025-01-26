import { useParams } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Chip,
  Divider,
  Button,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import Grid2 from '@mui/material/Grid';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
} from '@mui/lab';

// Mock data - will be replaced with real API data
const mockAlertDetail = {
  id: 1,
  timestamp: '2024-03-15T10:30:00Z',
  priority: 'CRITICAL',
  source: '192.168.1.100',
  destination: '10.0.0.5',
  message: 'Potential data exfiltration detected',
  state: 'NEW',
  assignee: null,
  protocol: 'TCP',
  port: 443,
  enrichmentData: {
    geoip_source: {
      country: 'United States',
      city: 'San Francisco',
      coordinates: [-122.4194, 37.7749],
      asn: 'AS12345',
      isp: 'Example ISP',
    },
    reputation_source: {
      score: 85,
      categories: ['malware', 'c2'],
      lastSeen: '2024-03-14T00:00:00Z',
      confidence: 0.9,
    },
  },
  tags: ['network:internal', 'protocol:tcp', 'severity:critical'],
  timeline: [
    {
      timestamp: '2024-03-15T10:30:00Z',
      event: 'Alert Created',
      details: 'Alert generated by network monitoring system',
    },
    {
      timestamp: '2024-03-15T10:31:00Z',
      event: 'Enrichment Complete',
      details: 'Alert enriched with threat intelligence data',
    },
  ],
};

export default function AlertDetail() {
  // The id parameter will be used to fetch alert details from the API
  // Currently using mock data until API integration is implemented
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { id } = useParams();

  // In a real implementation, we would fetch the alert details using the ID
  const alert = mockAlertDetail; // TODO: Replace with API call: fetchAlertDetails(id);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom>
        Alert Details
      </Typography>

      <Grid2 container spacing={3}>
        {/* Alert Overview */}
        <Grid2 item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Grid2 container spacing={2}>
              <Grid2 item xs={12} md={8}>
                <Typography variant="h5" gutterBottom>
                  {alert.message}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                  <Chip
                    label={alert.priority}
                    color="error"
                    sx={{ fontWeight: 'bold' }}
                  />
                  <Chip label={alert.state} color="warning" />
                  <Chip
                    label={alert.assignee || 'Unassigned'}
                    color="default"
                  />
                </Box>
              </Grid2>
              <Grid2 item xs={12} md={4} sx={{ textAlign: 'right' }}>
                <Button
                  variant="contained"
                  color="primary"
                  sx={{ mr: 1 }}
                  onClick={() => {
                    // Handle acknowledge
                  }}
                >
                  Acknowledge
                </Button>
                <Button
                  variant="contained"
                  color="success"
                  onClick={() => {
                    // Handle resolve
                  }}
                >
                  Resolve
                </Button>
              </Grid2>
            </Grid2>
          </Paper>
        </Grid2>

        {/* Alert Details */}
        <Grid2 item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Network Details
              </Typography>
              <List>
                <ListItem>
                  <ListItemText
                    primary="Source"
                    secondary={alert.source}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Destination"
                    secondary={alert.destination}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Protocol"
                    secondary={`${alert.protocol}:${alert.port}`}
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid2>

        {/* Enrichment Data */}
        <Grid2 item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Enrichment Data
              </Typography>
              <Typography variant="subtitle2">GeoIP Information</Typography>
              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Location"
                    secondary={`${alert.enrichmentData.geoip_source.city}, ${alert.enrichmentData.geoip_source.country}`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Network"
                    secondary={`${alert.enrichmentData.geoip_source.asn} (${alert.enrichmentData.geoip_source.isp})`}
                  />
                </ListItem>
              </List>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2">Threat Intelligence</Typography>
              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Reputation Score"
                    secondary={`${alert.enrichmentData.reputation_source.score}/100`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Categories"
                    secondary={alert.enrichmentData.reputation_source.categories.join(', ')}
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid2>

        {/* Timeline */}
        <Grid2 item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Alert Timeline
            </Typography>
            <Timeline>
              {alert.timeline.map((event, index) => (
                <TimelineItem key={index}>
                  <TimelineSeparator>
                    <TimelineDot color="primary" />
                    {index < alert.timeline.length - 1 && <TimelineConnector />}
                  </TimelineSeparator>
                  <TimelineContent>
                    <Typography variant="subtitle2">{event.event}</Typography>
                    <Typography variant="body2" color="textSecondary">
                      {new Date(event.timestamp).toLocaleString()}
                    </Typography>
                    <Typography variant="body2">{event.details}</Typography>
                  </TimelineContent>
                </TimelineItem>
              ))}
            </Timeline>
          </Paper>
        </Grid2>

        {/* Tags */}
        <Grid2 item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Tags
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              {alert.tags.map((tag) => (
                <Chip key={tag} label={tag} />
              ))}
            </Box>
          </Paper>
        </Grid2>
      </Grid2>
    </Box>
  );
} 