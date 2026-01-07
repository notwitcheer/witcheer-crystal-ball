"""
Web dashboard for monitoring Witcher's Crystal Ball alerts and performance.

Provides secure web interface for viewing alerts, performance metrics,
wallet analysis, and system status with role-based authentication.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import secrets
import hashlib

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
import jwt
from passlib.context import CryptContext

from ..storage.database import Database
from ..performance.tracker import PerformanceTracker
from ..clustering.wallet_clustering import WalletClusteringEngine
from ..config import Config


class UserCredentials(BaseModel):
    """User login credentials."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class DashboardUser(BaseModel):
    """Dashboard user model."""
    id: int
    username: str
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None
    active: bool = True


class AlertSummary(BaseModel):
    """Alert summary for dashboard display."""
    id: int
    wallet_address: str
    market_name: str
    suspicion_score: int
    position_size_usd: float
    position_side: str
    status: str
    created_at: datetime
    outcome: Optional[str] = None


class PerformanceSummary(BaseModel):
    """Performance metrics summary."""
    total_alerts: int
    resolved_alerts: int
    win_rate: float
    total_pnl: float
    sharpe_ratio: float
    max_drawdown: float
    avg_suspicion_score: float


class DashboardAuth:
    """Authentication handler for dashboard."""

    def __init__(self, config: Config):
        self.config = config
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.security = HTTPBearer()
        self.secret_key = config.dashboard.secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = config.dashboard.access_token_expire_minutes

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return self.pwd_context.hash(password)

    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    async def verify_token(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> DashboardUser:
        """Verify JWT token and return user."""
        try:
            payload = jwt.decode(credentials.credentials, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user from database
        async with Database() as db:
            user_data = await db.fetch_one(
                "SELECT * FROM dashboard_users WHERE username = ? AND active = 1",
                (username,)
            )

            if user_data is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive",
                )

            return DashboardUser(
                id=user_data['id'],
                username=user_data['username'],
                role=user_data['role'],
                created_at=user_data['created_at'],
                last_login=user_data['last_login'],
                active=bool(user_data['active'])
            )


class CrystalBallDashboard:
    """Main dashboard application."""

    def __init__(self, config: Config):
        self.config = config
        self.auth = DashboardAuth(config)
        self.app = FastAPI(
            title="Witcher's Crystal Ball Dashboard",
            description="Monitor insider activity detection and performance",
            version="1.0.0"
        )

        # Security middleware
        self.app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=config.dashboard.allowed_hosts.split(",")
        )

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=config.dashboard.cors_origins.split(","),
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

        # Setup routes
        self._setup_routes()

        # Initialize components
        self.performance_tracker = None
        self.clustering_engine = None

    async def startup(self):
        """Initialize dashboard components."""
        from ..storage.database import Database
        db = Database()
        self.performance_tracker = PerformanceTracker(db)
        self.clustering_engine = WalletClusteringEngine()

        # Create dashboard tables if they don't exist
        await self._create_dashboard_tables()

        # Create default admin user if none exists
        await self._create_default_admin()

    async def _create_dashboard_tables(self):
        """Create dashboard-specific database tables."""
        db = Database()
        await db.initialize()
        cursor = await db._get_cursor()

        try:
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)

            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_token TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES dashboard_users(id)
                )
            """)
        finally:
            await db.close()

    async def _create_default_admin(self):
        """Create default admin user if none exists."""
        async with Database() as db:
            admin_exists = await db.fetch_one(
                "SELECT id FROM dashboard_users WHERE role = 'admin'"
            )

            if not admin_exists:
                default_password = secrets.token_urlsafe(16)
                password_hash = self.auth.get_password_hash(default_password)

                await db.execute(
                    """INSERT INTO dashboard_users (username, password_hash, role)
                       VALUES (?, ?, ?)""",
                    ("admin", password_hash, "admin")
                )

                print(f"Created default admin user:")
                print(f"Username: admin")
                print(f"Password: {default_password}")
                print("Please change this password immediately!")

    def _setup_routes(self):
        """Setup all dashboard routes."""

        @self.app.post("/auth/login")
        async def login(credentials: UserCredentials):
            """User login endpoint."""
            async with Database() as db:
                user_data = await db.fetch_one(
                    "SELECT * FROM dashboard_users WHERE username = ? AND active = 1",
                    (credentials.username,)
                )

                if not user_data or not self.auth.verify_password(
                    credentials.password, user_data['password_hash']
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Incorrect username or password",
                    )

                # Update last login
                await db.execute(
                    "UPDATE dashboard_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_data['id'],)
                )

                # Create access token
                access_token = self.auth.create_access_token(
                    data={"sub": user_data['username'], "role": user_data['role']}
                )

                return {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "user": {
                        "username": user_data['username'],
                        "role": user_data['role']
                    }
                }

        @self.app.get("/api/dashboard/summary")
        async def get_dashboard_summary(current_user: DashboardUser = Depends(self.auth.verify_token)):
            """Get dashboard summary statistics."""
            async with Database() as db:
                # Get alert counts
                alert_stats = await db.fetch_one("""
                    SELECT
                        COUNT(*) as total_alerts,
                        SUM(CASE WHEN outcome IS NOT NULL THEN 1 ELSE 0 END) as resolved_alerts,
                        AVG(suspicion_score) as avg_suspicion_score
                    FROM alerts
                    WHERE created_at >= datetime('now', '-30 days')
                """)

                # Get performance metrics
                performance_stats = await db.fetch_one("""
                    SELECT
                        COUNT(*) as total_outcomes,
                        SUM(CASE WHEN outcome = 'WIN' THEN 1 ELSE 0 END) as wins,
                        SUM(pnl_usd) as total_pnl
                    FROM performance
                    WHERE created_at >= datetime('now', '-30 days')
                """)

                win_rate = 0.0
                if performance_stats['total_outcomes'] > 0:
                    win_rate = performance_stats['wins'] / performance_stats['total_outcomes']

                return {
                    "total_alerts": alert_stats['total_alerts'] or 0,
                    "resolved_alerts": alert_stats['resolved_alerts'] or 0,
                    "win_rate": win_rate,
                    "total_pnl": performance_stats['total_pnl'] or 0.0,
                    "avg_suspicion_score": alert_stats['avg_suspicion_score'] or 0.0
                }

        @self.app.get("/api/alerts/recent")
        async def get_recent_alerts(
            limit: int = 50,
            current_user: DashboardUser = Depends(self.auth.verify_token)
        ):
            """Get recent alerts."""
            async with Database() as db:
                alerts_data = await db.fetch_all("""
                    SELECT
                        a.id,
                        a.wallet_address,
                        a.market_id,
                        a.event_slug as market_name,
                        a.suspicion_score,
                        a.position_size_usd,
                        a.position_side,
                        a.outcome,
                        a.created_at,
                        CASE
                            WHEN a.outcome IS NULL THEN 'pending'
                            ELSE 'resolved'
                        END as status
                    FROM alerts a
                    ORDER BY a.created_at DESC
                    LIMIT ?
                """, (limit,))

                return [
                    AlertSummary(
                        id=alert['id'],
                        wallet_address=alert['wallet_address'],
                        market_name=alert['market_name'],
                        suspicion_score=alert['suspicion_score'],
                        position_size_usd=alert['position_size_usd'],
                        position_side=alert['position_side'],
                        status=alert['status'],
                        created_at=alert['created_at'],
                        outcome=alert['outcome']
                    )
                    for alert in alerts_data
                ]

        @self.app.get("/api/performance/metrics")
        async def get_performance_metrics(
            days: int = 30,
            current_user: DashboardUser = Depends(self.auth.verify_token)
        ):
            """Get performance metrics for specified period."""
            if self.performance_tracker:
                metrics = await self.performance_tracker.get_performance_metrics(days)
                return metrics.dict()
            else:
                return {"error": "Performance tracker not initialized"}

        @self.app.get("/api/wallets/suspicious")
        async def get_suspicious_wallets(
            limit: int = 20,
            current_user: DashboardUser = Depends(self.auth.verify_token)
        ):
            """Get most suspicious wallets."""
            async with Database() as db:
                wallets_data = await db.fetch_all("""
                    SELECT
                        w.address,
                        w.total_trades,
                        w.total_volume_usd,
                        w.win_rate,
                        w.first_seen,
                        COUNT(a.id) as alert_count,
                        AVG(a.suspicion_score) as avg_suspicion_score
                    FROM wallets w
                    LEFT JOIN alerts a ON w.address = a.wallet_address
                    GROUP BY w.address
                    HAVING alert_count > 0
                    ORDER BY avg_suspicion_score DESC, alert_count DESC
                    LIMIT ?
                """, (limit,))

                return [
                    {
                        "address": wallet['address'],
                        "total_trades": wallet['total_trades'],
                        "total_volume_usd": wallet['total_volume_usd'],
                        "win_rate": wallet['win_rate'],
                        "first_seen": wallet['first_seen'],
                        "alert_count": wallet['alert_count'],
                        "avg_suspicion_score": wallet['avg_suspicion_score']
                    }
                    for wallet in wallets_data
                ]

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }


async def create_dashboard_app(config: Config) -> FastAPI:
    """Create and configure dashboard application."""
    dashboard = CrystalBallDashboard(config)
    await dashboard.startup()
    return dashboard.app


if __name__ == "__main__":
    import uvicorn
    from ..config import load_config

    async def main():
        config = load_config()
        app = await create_dashboard_app(config)

        uvicorn.run(
            app,
            host=config.dashboard.host,
            port=config.dashboard.port,
            log_level="info"
        )

    asyncio.run(main())