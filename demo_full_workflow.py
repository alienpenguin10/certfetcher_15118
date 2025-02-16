import asyncio
import logging
from pathlib import Path

from oem_provisioning import OEMCertificateGenerator
from iso15118.evcc import Config as EVCCConfig, EVCCHandler
from iso15118.secc import SECCHandler
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.secc_settings import Config as SECCConfig
from iso15118.shared.exificient_exi_codec import ExificientEXICodec
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.evcc_config import load_from_file as load_evcc_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

"""
This script will:
Generate OEM Provisioning Certificates
Simulate Contract Certificate Installation
Start both EVCC and SECC handlers
Simulate a charging session with message exchanges
Log the progress of the charging session
"""


async def generate_certificates():
    generator = OEMCertificateGenerator(
        version="iso-2",
        password="secure_password_123",
        provcertname="MY_EV_CERT"
    )
    generator.execute()
    logger.info("OEM Certificates generated successfully")


async def install_contract_certificate():
    # This is a placeholder. In reality, this would involve
    # communication with a Certificate Provisioning Service.
    logger.info("Contract Certificate installation simulated")


async def run_evcc():
    config = EVCCConfig()
    config.load_envs()
    evcc_config = await load_evcc_config(config.ev_config_file_path)
    evcc_handler = EVCCHandler(
        evcc_config=evcc_config,
        iface=config.iface,
        exi_codec=ExificientEXICodec(),
        ev_controller=SimEVController(evcc_config),
    )
    await evcc_handler.start()


async def run_secc():
    config = SECCConfig()
    config.load_envs()
    sim_evse_controller = SimEVSEController()
    secc_handler = SECCHandler(
        exi_codec=ExificientEXICodec(),
        evse_controller=sim_evse_controller,
        config=config,
    )
    await secc_handler.start(config.iface)


async def simulate_charging_session():
    # This function will coordinate EVCC and SECC communication
    evcc_task = asyncio.create_task(run_evcc())
    secc_task = asyncio.create_task(run_secc())

    # Wait for both to initialize
    await asyncio.sleep(5)

    # Here we'd typically see message exchanges, but we'll simulate with logs
    logger.info("EVCC sends SessionSetupReq")
    await asyncio.sleep(1)
    logger.info("SECC responds with SessionSetupRes")
    await asyncio.sleep(1)
    logger.info("EVCC sends PaymentDetailsReq")
    await asyncio.sleep(1)
    logger.info("SECC responds with PaymentDetailsRes")
    await asyncio.sleep(1)
    logger.info("EVCC sends ChargeParameterDiscoveryReq")
    await asyncio.sleep(1)
    logger.info("SECC responds with ChargeParameterDiscoveryRes")
    await asyncio.sleep(1)
    logger.info("Charging session established")

    # Simulate charging for 10 seconds
    for i in range(10):
        logger.info(f"Charging in progress: {i + 1}0%")
        await asyncio.sleep(1)

    logger.info("Charging session completed")

    # Cancel the EVCC and SECC tasks
    evcc_task.cancel()
    secc_task.cancel()
    try:
        await evcc_task
        await secc_task
    except asyncio.CancelledError:
        pass


async def main():
    await generate_certificates()
    await install_contract_certificate()
    await simulate_charging_session()


if __name__ == "__main__":
    asyncio.run(main())

