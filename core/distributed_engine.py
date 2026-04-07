"""
core/distributed_engine.py - Multi-agent coordination for distributed scanning

Provides coordination and communication capabilities for distributed scanning
across multiple agents/nodes for large-scale reconnaissance operations.
"""

import asyncio
import json
import time
import hashlib
import socket
import threading
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import logging
import pickle
import base64
import redis
import zmq

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Status of distributed agents"""
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    ERROR = "error"
    OFFLINE = "offline"


class TaskType(Enum):
    """Types of distributed tasks"""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ANALYZE = "analyze"
    REPORT = "report"


@dataclass
class AgentInfo:
    """Information about a distributed agent"""
    agent_id: str
    hostname: str
    ip_address: str
    port: int
    status: AgentStatus = AgentStatus.IDLE
    capabilities: List[str] = field(default_factory=list)
    current_task: Optional[str] = None
    last_heartbeat: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    load_average: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0


@dataclass
class DistributedTask:
    """A task to be distributed to agents"""
    task_id: str
    task_type: TaskType
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    assigned_agent: Optional[str] = None
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3


class DistributedEngine:
    """
    Distributed scanning engine for coordinating multiple agents.
    
    Features:
    - Multi-agent coordination via Redis pub/sub or ZeroMQ
    - Load balancing across agents
    - Task queuing and prioritization
    - Fault tolerance with automatic failover
    - Real-time progress tracking
    - Result aggregation from multiple agents
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        zmq_port: int = 5555,
        use_redis: bool = True,
        heartbeat_interval: float = 5.0,
        agent_timeout: float = 30.0,
    ):
        self.agent_id = agent_id or self._generate_agent_id()
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.zmq_port = zmq_port
        self.use_redis = use_redis
        self.heartbeat_interval = heartbeat_interval
        self.agent_timeout = agent_timeout
        
        # Agent registry
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_lock = threading.Lock()
        
        # Task management
        self.task_queue: List[DistributedTask] = []
        self.active_tasks: Dict[str, DistributedTask] = {}
        self.completed_tasks: Dict[str, DistributedTask] = {}
        self.task_lock = threading.Lock()
        
        # Communication
        self.redis_client: Optional[redis.Redis] = None
        self.zmq_context: Optional[zmq.Context] = None
        self.zmq_socket: Optional[zmq.Socket] = None
        
        # Callbacks
        self._on_agent_join: Optional[callable] = None
        self._on_agent_leave: Optional[callable] = None
        self._on_task_complete: Optional[callable] = None
        self._on_task_error: Optional[callable] = None
        
        # Running state
        self._running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            'agents_online': 0,
            'agents_offline': 0,
            'tasks_queued': 0,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'tasks_retried': 0,
        }
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return f"agent-{hostname}-{ip}-{int(time.time())}"
    
    def _initialize_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")
            return True
        except redis.ConnectionError as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            return False
    
    def _initialize_zmq(self):
        """Initialize ZeroMQ sockets"""
        try:
            self.zmq_context = zmq.Context()
            self.zmq_socket = self.zmq_context.socket(zmq.ROUTER)
            self.zmq_socket.bind(f"tcp://*:{self.zmq_port}")
            logger.info(f"ZeroMQ bound to port {self.zmq_port}")
            return True
        except zmq.ZMQError as e:
            logger.warning(f"Failed to initialize ZeroMQ: {e}")
            return False
    
    def start(self):
        """Start the distributed engine"""
        self._running = True
        
        # Initialize communication
        if self.use_redis:
            if not self._initialize_redis():
                logger.warning("Redis not available, falling back to local mode")
        else:
            if not self._initialize_zmq():
                logger.warning("ZeroMQ not available, falling back to local mode")
        
        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self._heartbeat_thread.daemon = True
        self._heartbeat_thread.start()
        
        logger.info(f"Distributed engine started with agent ID: {self.agent_id}")
    
    def stop(self):
        """Stop the distributed engine"""
        self._running = False
        
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        
        if self.zmq_socket:
            self.zmq_socket.close()
        if self.zmq_context:
            self.zmq_context.term()
        
        logger.info("Distributed engine stopped")
    
    def _heartbeat_loop(self):
        """Heartbeat loop for agent communication"""
        while self._running:
            try:
                # Send heartbeat
                self._send_heartbeat()
                
                # Check agent health
                self._check_agent_health()
                
                # Process incoming messages
                self._process_messages()
                
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
            
            time.sleep(self.heartbeat_interval)
    
    def _send_heartbeat(self):
        """Send heartbeat to coordination server"""
        if self.redis_client:
            try:
                heartbeat_data = {
                    'agent_id': self.agent_id,
                    'timestamp': time.time(),
                    'status': AgentStatus.IDLE.value if not self.active_tasks else AgentStatus.SCANNING.value,
                    'tasks_completed': self.stats['tasks_completed'],
                    'tasks_failed': self.stats['tasks_failed'],
                }
                
                self.redis_client.hset(
                    'agents:heartbeats',
                    self.agent_id,
                    json.dumps(heartbeat_data)
                )
            except redis.RedisError as e:
                logger.error(f"Failed to send heartbeat: {e}")
    
    def _check_agent_health(self):
        """Check health of all agents"""
        if not self.redis_client:
            return
        
        try:
            agents_data = self.redis_client.hgetall('agents:heartbeats')
            current_time = time.time()
            
            with self.agent_lock:
                for agent_id, data_str in agents_data.items():
                    try:
                        data = json.loads(data_str)
                        last_heartbeat = data.get('timestamp', 0)
                        
                        if agent_id in self.agents:
                            # Update existing agent
                            agent = self.agents[agent_id]
                            if current_time - last_heartbeat > self.agent_timeout:
                                if agent.status != AgentStatus.OFFLINE:
                                    agent.status = AgentStatus.OFFLINE
                                    self.stats['agents_offline'] += 1
                                    self.stats['agents_online'] -= 1
                                    if self._on_agent_leave:
                                        self._on_agent_leave(agent)
                            else:
                                if agent.status == AgentStatus.OFFLINE:
                                    agent.status = AgentStatus.IDLE
                                    self.stats['agents_online'] += 1
                                    self.stats['agents_offline'] -= 1
                                    if self._on_agent_join:
                                        self._on_agent_join(agent)
                        else:
                            # New agent
                            agent = AgentInfo(
                                agent_id=agent_id,
                                hostname=data.get('hostname', 'unknown'),
                                ip_address=data.get('ip', 'unknown'),
                                port=data.get('port', 0),
                                status=AgentStatus.IDLE if current_time - last_heartbeat <= self.agent_timeout else AgentStatus.OFFLINE,
                            )
                            self.agents[agent_id] = agent
                            if agent.status == AgentStatus.IDLE:
                                self.stats['agents_online'] += 1
                                if self._on_agent_join:
                                    self._on_agent_join(agent)
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"Failed to parse agent data: {e}")
        except redis.RedisError as e:
            logger.error(f"Failed to check agent health: {e}")
    
    def _process_messages(self):
        """Process incoming messages from agents"""
        if not self.redis_client:
            return
        
        try:
            # Check for task completions
            task_results = self.redis_client.lrange('task:results', 0, -1)
            if task_results:
                self.redis_client.delete('task:results')
                
                for result_str in task_results:
                    try:
                        result = json.loads(result_str)
                        task_id = result.get('task_id')
                        
                        with self.task_lock:
                            if task_id in self.active_tasks:
                                task = self.active_tasks[task_id]
                                task.status = 'completed'
                                task.result = result.get('result')
                                task.completed_at = time.time()
                                
                                self.completed_tasks[task_id] = task
                                del self.active_tasks[task_id]
                                self.stats['tasks_completed'] += 1
                                
                                if self._on_task_complete:
                                    self._on_task_complete(task)
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"Failed to process task result: {e}")
        except redis.RedisError as e:
            logger.error(f"Failed to process messages: {e}")
    
    def register_agent(
        self,
        hostname: str,
        ip_address: str,
        port: int,
        capabilities: List[str] = None,
    ) -> str:
        """Register a new agent"""
        agent = AgentInfo(
            agent_id=self._generate_agent_id(),
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            capabilities=capabilities or [],
            status=AgentStatus.IDLE,
            last_heartbeat=time.time(),
        )
        
        with self.agent_lock:
            self.agents[agent.agent_id] = agent
        
        self.stats['agents_online'] += 1
        
        if self._on_agent_join:
            self._on_agent_join(agent)
        
        logger.info(f"Agent registered: {agent.agent_id}")
        return agent.agent_id
    
    def submit_task(
        self,
        task_type: TaskType,
        target: str,
        parameters: Dict[str, Any] = None,
        priority: int = 0,
    ) -> str:
        """Submit a task for distributed execution"""
        task = DistributedTask(
            task_id=hashlib.md5(f"{task_type.value}:{target}:{time.time()}".encode()).hexdigest()[:12],
            task_type=task_type,
            target=target,
            parameters=parameters or {},
            priority=priority,
        )
        
        with self.task_lock:
            self.task_queue.append(task)
            self.task_queue.sort(key=lambda t: t.priority, reverse=True)
            self.stats['tasks_queued'] += 1
        
        # Try to assign immediately if agents available
        self._try_assign_tasks()
        
        logger.info(f"Task submitted: {task.task_id} ({task_type.value} - {target})")
        return task.task_id
    
    def _try_assign_tasks(self):
        """Try to assign pending tasks to available agents"""
        with self.agent_lock:
            available_agents = [
                agent for agent in self.agents.values()
                if agent.status == AgentStatus.IDLE
            ]
        
        if not available_agents:
            return
        
        with self.task_lock:
            tasks_to_assign = []
            while self.task_queue and available_agents:
                task = self.task_queue.pop(0)
                agent = available_agents.pop(0)
                tasks_to_assign.append((task, agent))
        
        for task, agent in tasks_to_assign:
            self._assign_task_to_agent(task, agent)
    
    def _assign_task_to_agent(self, task: DistributedTask, agent: AgentInfo):
        """Assign a specific task to an agent"""
        task.assigned_agent = agent.agent_id
        task.status = 'assigned'
        task.started_at = time.time()
        
        agent.status = AgentStatus.SCANNING
        agent.current_task = task.task_id
        
        with self.task_lock:
            self.active_tasks[task.task_id] = task
        
        # Send task to agent via Redis
        if self.redis_client:
            try:
                task_data = {
                    'task_id': task.task_id,
                    'task_type': task.task_type.value,
                    'target': task.target,
                    'parameters': task.parameters,
                    'priority': task.priority,
                }
                
                self.redis_client.publish(
                    f'agent:{agent.agent_id}:tasks',
                    json.dumps(task_data)
                )
                
                logger.info(f"Task {task.task_id} assigned to agent {agent.agent_id}")
            except redis.RedisError as e:
                logger.error(f"Failed to assign task: {e}")
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get status of a specific task"""
        with self.task_lock:
            if task_id in self.active_tasks:
                task = self.active_tasks[task_id]
                return {
                    'task_id': task.task_id,
                    'status': task.status,
                    'assigned_agent': task.assigned_agent,
                    'progress': self._calculate_task_progress(task),
                }
            elif task_id in self.completed_tasks:
                task = self.completed_tasks[task_id]
                return {
                    'task_id': task.task_id,
                    'status': 'completed',
                    'result': task.result,
                    'completed_at': task.completed_at,
                }
        return None
    
    def _calculate_task_progress(self, task: DistributedTask) -> float:
        """Calculate progress of a task (0-100)"""
        if not task.started_at:
            return 0.0
        
        elapsed = time.time() - task.started_at
        # Estimate progress based on elapsed time (simplified)
        estimated_duration = 60.0  # Assume 60 seconds average
        progress = min(100.0, (elapsed / estimated_duration) * 100)
        return progress
    
    def get_agent_stats(self) -> Dict:
        """Get statistics about all agents"""
        with self.agent_lock:
            return {
                'total_agents': len(self.agents),
                'online_agents': sum(1 for a in self.agents.values() if a.status != AgentStatus.OFFLINE),
                'offline_agents': sum(1 for a in self.agents.values() if a.status == AgentStatus.OFFLINE),
                'busy_agents': sum(1 for a in self.agents.values() if a.status == AgentStatus.SCANNING),
                'idle_agents': sum(1 for a in self.agents.values() if a.status == AgentStatus.IDLE),
                'agents': {
                    agent_id: {
                        'status': agent.status.value,
                        'current_task': agent.current_task,
                        'tasks_completed': agent.tasks_completed,
                        'tasks_failed': agent.tasks_failed,
                    }
                    for agent_id, agent in self.agents.items()
                }
            }
    
    def get_queue_stats(self) -> Dict:
        """Get statistics about task queue"""
        with self.task_lock:
            return {
                'queued_tasks': len(self.task_queue),
                'active_tasks': len(self.active_tasks),
                'completed_tasks': len(self.completed_tasks),
                'stats': self.stats.copy(),
            }
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or active task"""
        with self.task_lock:
            # Check if in queue
            for i, task in enumerate(self.task_queue):
                if task.task_id == task_id:
                    del self.task_queue[i]
                    return True
            
            # Check if active
            if task_id in self.active_tasks:
                task = self.active_tasks[task_id]
                task.status = 'cancelled'
                
                # Free up the agent
                if task.assigned_agent and task.assigned_agent in self.agents:
                    agent = self.agents[task.assigned_agent]
                    agent.status = AgentStatus.IDLE
                    agent.current_task = None
                
                del self.active_tasks[task_id]
                return True
        
        return False
    
    def broadcast_command(self, command: str, parameters: Dict = None):
        """Broadcast a command to all agents"""
        if not self.redis_client:
            return
        
        command_data = {
            'command': command,
            'parameters': parameters or {},
            'timestamp': time.time(),
        }
        
        try:
            self.redis_client.publish(
                'agents:commands',
                json.dumps(command_data)
            )
        except redis.RedisError as e:
            logger.error(f"Failed to broadcast command: {e}")
    
    def pause_all_agents(self):
        """Pause all agents"""
        self.broadcast_command('pause')
    
    def resume_all_agents(self):
        """Resume all paused agents"""
        self.broadcast_command('resume')
    
    def shutdown_all_agents(self):
        """Gracefully shutdown all agents"""
        self.broadcast_command('shutdown')


class DistributedScanner:
    """
    High-level distributed scanner that uses DistributedEngine.
    
    Provides a simple interface for distributing scanning tasks
    across multiple agents.
    """
    
    def __init__(self, engine: DistributedEngine):
        self.engine = engine
        self.results: Dict[str, Any] = {}
    
    def scan_target(
        self,
        target: str,
        scan_type: str = "full",
        priority: int = 0,
    ) -> str:
        """
        Submit a target for distributed scanning.
        
        Returns task ID for tracking.
        """
        parameters = {
            'scan_type': scan_type,
            'modules': self._get_modules_for_scan_type(scan_type),
        }
        
        return self.engine.submit_task(
            TaskType.SCAN,
            target,
            parameters,
            priority,
        )
    
    def _get_modules_for_scan_type(self, scan_type: str) -> List[str]:
        """Get list of modules to run based on scan type"""
        scan_types = {
            'light': ['recon', 'live_hosts', 'basic_scan'],
            'standard': ['recon', 'live_hosts', 'crawl', 'scan', 'analyze'],
            'full': ['recon', 'live_hosts', 'wordpress', 'toolkit', 'crawl', 'classify', 'rank', 'scan', 'analyze', 'graph', 'chain', 'exploit'],
            'stealth': ['recon', 'live_hosts', 'passive_scan'],
        }
        return scan_types.get(scan_type, scan_types['standard'])
    
    def wait_for_completion(
        self,
        task_id: str,
        timeout: float = None,
        poll_interval: float = 1.0,
    ) -> Optional[Dict]:
        """
        Wait for a task to complete.
        
        Returns task result when complete, or None if timeout.
        """
        start_time = time.time()
        
        while True:
            status = self.engine.get_task_status(task_id)
            if status is None:
                return None
            
            if status['status'] in ['completed', 'cancelled', 'failed']:
                return status
            
            if timeout and (time.time() - start_time) > timeout:
                return None
            
            time.sleep(poll_interval)
    
    def get_results(self, task_id: str) -> Optional[Dict]:
        """Get results for a completed task"""
        status = self.engine.get_task_status(task_id)
        if status and status.get('status') == 'completed':
            return status.get('result')
        return None