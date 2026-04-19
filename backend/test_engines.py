import asyncio
from app.models.database import AsyncSessionLocal
from app.core.violations_engine import run_violations_engine
from app.core.dspm_engine import run_dspm_engine
import structlog

async def main():
    async with AsyncSessionLocal() as db:
        print("Running Violations Engine...")
        v_created = await run_violations_engine(db)
        print(f"Violations created: {v_created}")
        
        print("Running DSPM Engine...")
        d_created = await run_dspm_engine(db, enrich=False)
        print(f"DSPM Findings created: {d_created}")
        
        await db.commit()

if __name__ == "__main__":
    asyncio.run(main())
