from eth2.beacon.deposit_contract import IDepositContract
from eth2.beacon.deposit_data import DepositData
from eth2.beacon.signature_helpers import sign_deposit_data
from eth2.utils.ssz import encode_ssz

def submit_deposit_data(
    deposit_contract: IDepositContract,
    pubkey: bytes,
    withdrawal_credentials: bytes,
    signature: bytes,
    deposit_data_root: bytes32,
) -> None:
    deposit_data = DepositData(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        signature=signature,
    )

    encoded_deposit_data = encode_ssz(deposit_data)
    assert deposit_data_root == sha256(encoded_deposit_data).digest()

    deposit_contract.deposit(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        signature=signature,
        deposit_data_root=deposit_data_root,
    )

if __name__ == "__main__":
    deposit_contract = IDepositContract.deploy()

    pubkey = bytes.fromhex("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    withdrawal_credentials = bytes.fromhex(
        "0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    signature = bytes.fromhex(
        "0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
    )
    deposit_data_root = bytes.fromhex(
        "0x672b0185ac4dc1b7ef0fd4d0820a893c4862e648bacadef997957c3b825d9383"
    )

    submit_deposit_data(
        deposit_contract=deposit_contract,
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        signature=signature,
        deposit_data_root=deposit_data_root,
    )
