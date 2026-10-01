from collections.abc import Iterable
from typing import Any

from app.core.logging import get_logger
from app.sensors.base import Sensor, SensorResult
from app.sensors.http_payload_sensor import HttpPayloadSensor
from app.sensors.log_sentinel import LogSentinelSensor
from app.sensors.net_guard import NetGuardSensor
from app.sensors.netflow_sensor import NetflowSensor
from app.sensors.recon_sensor import ReconSensor

SENSOR_CLASSES: tuple[type[Sensor], ...] = (
    HttpPayloadSensor,
    NetflowSensor,
    LogSentinelSensor,
    NetGuardSensor,
    ReconSensor,
)

logger = get_logger("sensors.registry")


class UnknownSensorError(KeyError):
    pass


class SensorRegistry:
    def __init__(
        self,
        sensors: Iterable[Sensor],
        failures: dict[str, str] | None = None,
    ) -> None:
        self.sensors: dict[str, Sensor] = {}
        self.failures = failures or {}

        for sensor in sensors:
            if sensor.name in self.sensors:
                raise ValueError(f"duplicate sensor name '{sensor.name}'")
            self.sensors[sensor.name] = sensor

    @property
    def names(self) -> list[str]:
        return sorted(self.sensors)

    @property
    def is_complete(self) -> bool:
        return not self.failures

    def get(self, name: str) -> Sensor:
        sensor = self.sensors.get(name)

        if sensor is None:
            raise UnknownSensorError(name)

        return sensor

    def predict(self, name: str, payload: dict[str, Any]) -> SensorResult:
        return self.get(name).predict(payload)


def load_default_registry() -> SensorRegistry:
    sensors = []
    failures = {}

    for sensor_class in SENSOR_CLASSES:
        try:
            sensors.append(sensor_class())
        # one broken model must not stop the other sensors from loading
        except Exception as exc:
            failures[sensor_class.__name__] = str(exc)
            logger.error(
                "sensor failed to load: %s (%s)",
                sensor_class.__name__,
                exc,
            )

    return SensorRegistry(sensors, failures)
