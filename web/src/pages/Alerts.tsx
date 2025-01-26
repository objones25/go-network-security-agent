import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  DataGrid,
  GridColDef,
  GridRenderCellParams as GridRenderCellParamsType,
  GridToolbar,
} from '@mui/x-data-grid';
import {
  Visibility as ViewIcon,
  CheckCircle as ResolveIcon,
  Error as CriticalIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';

// Mock data - will be replaced with real API data
const mockAlerts = [
  {
    id: 1,
    timestamp: '2024-03-15T10:30:00Z',
    priority: 'CRITICAL',
    source: '192.168.1.100',
    destination: '10.0.0.5',
    message: 'Potential data exfiltration detected',
    state: 'NEW',
    assignee: null,
  },
  {
    id: 2,
    timestamp: '2024-03-15T10:25:00Z',
    priority: 'HIGH',
    source: '192.168.1.105',
    destination: '8.8.8.8',
    message: 'Suspicious outbound connection',
    state: 'ACKNOWLEDGED',
    assignee: 'analyst1',
  },
  // Add more mock alerts as needed
];

const priorityColors = {
  CRITICAL: '#ff5252',
  HIGH: '#ffd740',
  MEDIUM: '#40c4ff',
  LOW: '#69f0ae',
};

const stateColors = {
  NEW: '#ff5252',
  ACKNOWLEDGED: '#ffd740',
  IN_PROGRESS: '#40c4ff',
  RESOLVED: '#69f0ae',
  FALSE_POSITIVE: '#9e9e9e',
};

export default function Alerts() {
  const navigate = useNavigate();
  const [pageSize, setPageSize] = useState(10);

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return <CriticalIcon sx={{ color: priorityColors.CRITICAL }} />;
      case 'HIGH':
        return <WarningIcon sx={{ color: priorityColors.HIGH }} />;
      case 'MEDIUM':
        return <WarningIcon sx={{ color: priorityColors.MEDIUM }} />;
      case 'LOW':
        return <InfoIcon sx={{ color: priorityColors.LOW }} />;
      default:
        return null;
    }
  };

  const columns: GridColDef[] = [
    {
      field: 'priority',
      headerName: 'Priority',
      width: 120,
      renderCell: (params: GridRenderCellParamsType<any, any, any>) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {getPriorityIcon(params.value)}
          <Typography>{params.value}</Typography>
        </Box>
      ),
    },
    {
      field: 'timestamp',
      headerName: 'Time',
      width: 180,
      valueFormatter: ({ value }: { value: string }) => {
        return new Date(value).toLocaleString();
      },
    },
    {
      field: 'message',
      headerName: 'Message',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'source',
      headerName: 'Source',
      width: 150,
    },
    {
      field: 'destination',
      headerName: 'Destination',
      width: 150,
    },
    {
      field: 'state',
      headerName: 'State',
      width: 150,
      renderCell: (params: GridRenderCellParamsType<any, any, any>) => (
        <Chip
          label={params.value}
          sx={{
            backgroundColor: stateColors[params.value as keyof typeof stateColors],
            color: 'white',
          }}
        />
      ),
    },
    {
      field: 'assignee',
      headerName: 'Assignee',
      width: 150,
      renderCell: (params: GridRenderCellParamsType<any, any, any>) => (
        <Typography>{params.value || 'Unassigned'}</Typography>
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 120,
      sortable: false,
      renderCell: (params: GridRenderCellParamsType<any, any, any>) => (
        <Box>
          <Tooltip title="View Details">
            <IconButton
              onClick={() => navigate(`/alerts/${params.row.id}`)}
              size="small"
            >
              <ViewIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Mark as Resolved">
            <IconButton
              onClick={() => {
                // Handle resolve action
                console.log('Resolve alert:', params.row.id);
              }}
              size="small"
            >
              <ResolveIcon />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ];

  return (
    <Box sx={{ height: 'calc(100vh - 120px)', width: '100%' }}>
      <Typography variant="h4" gutterBottom>
        Alert Management
      </Typography>
      <Paper sx={{ height: '100%', width: '100%' }}>
        <DataGrid
          rows={mockAlerts}
          columns={columns}
          initialState={{
            pagination: {
              paginationModel: {
                pageSize: pageSize,
              },
            },
          }}
          pageSizeOptions={[5, 10, 20, 50]}
          onPaginationModelChange={(model) => setPageSize(model.pageSize)}
          checkboxSelection
          disableRowSelectionOnClick
          slots={{
            toolbar: GridToolbar,
          }}
          slotProps={{
            toolbar: {
              showQuickFilter: true,
              quickFilterProps: { debounceMs: 500 },
            },
          }}
        />
      </Paper>
    </Box>
  );
} 