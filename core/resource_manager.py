"""
core/resource_manager.py - Resource Management and Concurrency Control
Implements CONSTRAINT 3: Resource conservation for 4GB RAM systems with max 50 concurrent tasks.
"""

import logging
import threading
import time
import psutil
import os
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque

logger = logging.getLogger("recon.resource_manager")


@dataclass
class ResourceMetrics:
    """Current resource usage metrics."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    active_tasks: int
    pending_tasks: int
    task_queue_size: int
    
    def is_critical(self) -> bool:
        """Check if resource usage is critical."""
        return self.memory_percent > 85 or self.cpu_percent > 90

    def is_high(self) -> bool:
        """Check if resource usage is high."""
        return self.memory_percent > 70 or self.cpu_percent > 75


@dataclass
class TaskMetrics:
    """Metrics for a single task."""
    task_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = "pending"  # pending, running, completed, failed, timeout
    
    def is_stale(self, timeout_seconds: int = 30) -> bool:
        """Check if task has exceeded timeout."""
        if self.end_time is None:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            return elapsed > timeout_seconds
        return False


class ResourceManager:
    """
    Manages system resources and concurrency for 4GB RAM systems.
    
    Design:
    - Monitor CPU, memory, delays
    - Limit concurrent tasks to 50 max
    - Dynamically scale based on resource usage
    - Handle timeouts and backpressure
    
    CONSTRAINT: "Your hardware is limited (4GB RAM). Do not queue more than 50 concurrent tasks."
    CONSTRAINT: "If 'Timeout' occurs more than 3 times on a target, increase 'delay' by 2s and reduce 'concurrency'."
    """

    def __init__(
        self,
        max_concurrent_tasks: int = 50,
        max_memory_percent: float = 80.0,
        max_cpu_percent: float = 85.0,
        check_interval: float = 1.0
    ):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.max_memory_percent = max_memory_percent
        self.max_cpu_percent = max_cpu_percent
        self.check_interval = check_interval
        
        # Task tracking
        self.active_tasks: Dict[str, TaskMetrics] = {}
        self.task_history: deque = deque(maxlen=1000)  # Keep last 1000 tasks
        self.pending_count = 0
        
        # Resource tracking
        self.metrics_history: deque = deque(maxlen=3600)  # Keep last 3600 seconds
        self.last_metrics: Optional[ResourceMetrics] = None
        
        # Concurrency control
        self.current_concurrency = max_concurrent_tasks
        self.min_delay = 0.1  # Minimum delay between requests
        self.current_delay = 0.1
        self.process = psutil.Process(os.getpid())
        
        # Timeout tracking
        self.timeout_count = 0
        self.timeout_targets: Dict[str, int] = {}  # target -> timeout_count
        
        # Lock for thread safety
        self._lock = threading.Lock()

    def get_metrics(self) -> ResourceMetrics:
        """Get current resource metrics."""
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1) if hasattr(self.process, 'cpu_percent') else 0
            mem_info = self.process.memory_info()
            memory_mb = mem_info.rss / (1024 * 1024)  # Convert to MB
            
            # System-wide memory percentage
            vm = psutil.virtual_memory()
            memory_percent = vm.percent
        except Exception as e:
            logger.warning(f"[RESOURCE] Failed to get metrics: {e}")
            cpu_percent = 0
            memory_mb = 0
            memory_percent = 50  # Conservative estimate

        metrics = ResourceMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_mb=memory_mb,
            active_tasks=len(self.active_tasks),
            pending_tasks=self.pending_count,
            task_queue_size=self.pending_count
        )
        
        self.last_metrics = metrics
        self.metrics_history.append(metrics)
        
        return metrics

    def can_start_task(self) -> bool:
        """
        Check if system can start a new task.
        
        Returns: True if resources available, False if constrained
        """
        with self._lock:
            # Hard limit: max concurrent tasks
            if len(self.active_tasks) >= self.current_concurrency:
                logger.debug(f"[RESOURCE] Concurrency limit reached ({len(self.active_tasks)}/{self.current_concurrency})")
                return False
            
            # Check resource usage
            metrics = self.get_metrics()
            
            if metrics.is_critical():
                logger.warning(f"[RESOURCE] CRITICAL: Memory {metrics.memory_percent:.1f}%, CPU {metrics.cpu_percent:.1f}%")
                self._reduce_concurrency()
                return False
            
            if metrics.is_high():
                logger.info(f"[RESOURCE] HIGH: Memory {metrics.memory_percent:.1f}%, CPU {metrics.cpu_percent:.1f}%")
                # Allow but track it
                pass
            
            return True

    def register_task(self, task_id: str) -> bool:
        """Register a new task as active."""
        with self._lock:
            if not self.can_start_task():
                self.pending_count += 1
                logger.debug(f"[RESOURCE] Task {task_id} queued (pending: {self.pending_count})")
                return False
            
            self.active_tasks[task_id] = TaskMetrics(
                task_id=task_id,
                start_time=datetime.now(),
                status="running"
            )
            logger.debug(f"[RESOURCE] Task {task_id} started (active: {len(self.active_tasks)})")
            return True

    def unregister_task(self, task_id: str, status: str = "completed", error: Optional[str] = None):
        """Unregister a completed/failed task."""
        with self._lock:
            if task_id not in self.active_tasks:
                logger.debug(f"[RESOURCE] Task {task_id} not found in active tasks")
                return
            
            task = self.active_tasks[task_id]
            task.end_time = datetime.now()
            task.duration_seconds = (task.end_time - task.start_time).total_seconds()
            task.status = status
            
            # Move to history
            del self.active_tasks[task_id]
            self.task_history.append(task)
            
            # Check for stale tasks
            self._check_stale_tasks()
            
            logger.debug(f"[RESOURCE] Task {task_id} completed ({status}, {task.duration_seconds:.2f}s). "
                        f"Active: {len(self.active_tasks)}, Pending: {self.pending_count}")

    def wait_for_slot(self, timeout_seconds: int = 300) -> bool:
        """
        Wait for a task slot to become available.
        
        Returns: True if slot available, False if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            if self.can_start_task():
                return True
            
            time.sleep(self.check_interval)
        
        logger.warning(f"[RESOURCE] Wait for slot exceeded {timeout_seconds}s timeout")
        return False

    def get_delay(self) -> float:
        """Get recommended delay before next request."""
        metrics = self.get_metrics()
        
        # Scale delay based on resource usage
        if metrics.is_critical():
            return self.current_delay * 5
        elif metrics.is_high():
            return self.current_delay * 2
        else:
            return self.current_delay

    def on_timeout(self, target: str = "unknown"):
        """
        Record a timeout event.
        
        CONSTRAINT: If timeout > 3 times on a target:
        - increase delay by 2s
        - reduce concurrency by 10
        """
        with self._lock:
            self.timeout_count += 1
            self.timeout_targets[target] = self.timeout_targets.get(target, 0) + 1
            
            target_timeout_count = self.timeout_targets[target]
            
            if target_timeout_count > 3:
                logger.warning(f"[RESOURCE] {target_timeout_count} timeouts on {target} - escalating evasion")
                
                # Increase delay
                self.current_delay = min(self.current_delay + 2.0, 30.0)  # Cap at 30s
                
                # Reduce concurrency
                self.current_concurrency = max(self.current_concurrency - 10, 5)  # Min 5
                
                logger.warning(f"[RESOURCE] Adjusted: delay={self.current_delay:.1f}s, "
                              f"concurrency={self.current_concurrency}")

    def on_successful_request(self, target: str = "unknown"):
        """Reset timeout count on target after successful request."""
        with self._lock:
            if target in self.timeout_targets:
                # Slowly reduce timeout count (not instantly)
                self.timeout_targets[target] = max(0, self.timeout_targets[target] * 0.95)

    def _reduce_concurrency(self):
        """Reduce concurrency due to high resource usage."""
        old_concurrency = self.current_concurrency
        self.current_concurrency = max(self.current_concurrency - 5, 10)  # Min 10
        logger.warning(f"[RESOURCE] Reduced concurrency: {old_concurrency} → {self.current_concurrency}")

    def _check_stale_tasks(self):
        """Check for stale/hung tasks and clean them up."""
        timeout_seconds = 120  # 2 minute task timeout
        stale_tasks = [
            task_id for task_id, task in self.active_tasks.items()
            if task.is_stale(timeout_seconds)
        ]
        
        for task_id in stale_tasks:
            logger.warning(f"[RESOURCE] Stale task detected: {task_id}")
            self.unregister_task(task_id, status="timeout")

    def get_status(self) -> Dict:
        """Get current resource manager status."""
        with self._lock:
            metrics = self.last_metrics or self.get_metrics()
            
            return {
                'timestamp': metrics.timestamp.isoformat(),
                'memory_percent': metrics.memory_percent,
                'memory_mb': metrics.memory_mb,
                'cpu_percent': metrics.cpu_percent,
                'active_tasks': metrics.active_tasks,
                'pending_tasks': self.pending_count,
                'max_concurrent': self.current_concurrency,
                'current_delay': self.current_delay,
                'timeout_count': self.timeout_count,
                'timeout_by_target': dict(self.timeout_targets),
            }

    def should_abort_target(self, target: str) -> bool:
        """
        Determine if we should abort scanning for a target.
        
        CONSTRAINT: Too many timeouts + high resource usage → abort
        """
        if self.timeout_targets.get(target, 0) > 10:
            logger.warning(f"[RESOURCE] Aborting {target} - excessive timeouts")
            return True
        
        metrics = self.get_metrics()
        if metrics.is_critical():
            logger.warning(f"[RESOURCE] Aborting {target} - critical resource usage")
            return True
        
        return False

    def adaptive_sleep(self, base_delay: float = 0.1):
        """
        Sleep with resource-aware adaptation.
        
        CONSTRAINT: If resource high → longer delay
        """
        metrics = self.get_metrics()
        
        if metrics.is_critical():
            adjusted_delay = base_delay * 5
        elif metrics.is_high():
            adjusted_delay = base_delay * 2
        else:
            adjusted_delay = base_delay
        
        time.sleep(adjusted_delay)


class ConcurrencyController:
    """
    Manages concurrent task execution with resource limits.
    Uses semaphore to enforce concurrency limits.
    """

    def __init__(self, resource_manager: ResourceManager):
        self.resource_manager = resource_manager
        self.semaphore = threading.Semaphore(resource_manager.max_concurrent_tasks)
        self.active_tasks_lock = threading.Lock()

    def acquire(self, timeout: int = 300) -> bool:
        """Try to acquire concurrency slot."""
        return self.semaphore.acquire(timeout=timeout)

    def release(self):
        """Release concurrency slot."""
        self.semaphore.release()

    def get_available_slots(self) -> int:
        """Get number of available concurrency slots."""
        return self.resource_manager.current_concurrency - len(self.resource_manager.active_tasks)
