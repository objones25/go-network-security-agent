import { Grid, Paper, Typography, Box } from '@mui/material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

// Mock data - will be replaced with real API data
const alertsByPriority = [
  { name: 'Critical', value: 5, color: '#ff5252' },
  { name: 'High', value: 12, color: '#ffd740' },
  { name: 'Medium', value: 20, color: '#40c4ff' },
  { name: 'Low', value: 15, color: '#69f0ae' },
];

const alertsByTime = [
  { time: '00:00', alerts: 3 },
  { time: '04:00', alerts: 2 },
  { time: '08:00', alerts: 8 },
  { time: '12:00', alerts: 15 },
  { time: '16:00', alerts: 10 },
  { time: '20:00', alerts: 5 },
];

const StatCard = ({ title, value, color }: { title: string; value: number; color: string }) => (
  <Paper
    sx={{
      p: 3,
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'background.paper',
    }}
  >
    <Typography variant="h6" gutterBottom>
      {title}
    </Typography>
    <Typography variant="h3" sx={{ color }}>
      {value}
    </Typography>
  </Paper>
);

export default function Dashboard() {
  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom>
        Security Overview
      </Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Critical Alerts" value={5} color="#ff5252" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="High Priority" value={12} color="#ffd740" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Medium Priority" value={20} color="#40c4ff" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Low Priority" value={15} color="#69f0ae" />
        </Grid>

        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Alerts Over Time
            </Typography>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={alertsByTime}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="alerts" fill="#00b0ff" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Alerts by Priority
            </Typography>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={alertsByPriority}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label
                >
                  {alertsByPriority.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
} 