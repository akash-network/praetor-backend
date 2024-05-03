from pydantic import BaseModel
from typing import Optional


class DashboardPricePostRequest(BaseModel):
    session_id: str
    bid_price_cpu_scale: str = "1.60"  # USD/thread-month
    bid_price_memory_scale: str = "0.80"  # USD/GB-month
    bid_price_storage_scale: str = "0.02"  # USD/GB-month
    bid_price_hd_pres_hdd_scale: Optional[str] = "0.01"  # USD/GB-month (beta1)
    bid_price_hd_pres_ssd_scale: Optional[str] = "0.03"  # USD/GB-month (beta2)
    bid_price_hd_pres_nvme_scale: Optional[str] = "0.04"  # USD/GB-month (beta3)
    bid_price_endpoint_scale: Optional[str] = "0.05"  # USD for port/month
    bid_price_ip_scale: Optional[str] = "5"  # USD for IP/month
    bid_price_gpu_scale: Optional[str] = "100"  # USD/GPU unit a month
