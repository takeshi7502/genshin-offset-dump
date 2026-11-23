"""Verify candidate RVAs against our own GenshinImpact.exe 7.2.0.

For each candidate we report:
  - whether the RVA is a real .pdata function start
  - first 16 bytes
  - whether the first bytes contain a call/jmp thunk (bad) or a prologue (good)

This lets us accept/reject offsets independently of where the hint came from.
"""
import struct

import pefile

EXE = r"C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe"

CANDIDATES = {
    # name: rva
    "GetTypeInfoFromTypeDefinitionIndex": 0x527E20,
    "CheckTargetAttackable(A)": 0x1634160,
    "CheckTargetAttackable(B)": 0x131E7700,
    "GlobalVars": 0x586B480,
    "Application_set_targetFrameRate": 0x146C6C0,
    "QualitySettings_set_vSyncCount": 0x98ABB0,
    "Time_get_timeScale": 0x1448A00,
    "Time_set_timeScale": 0x1448A20,
    "Camera_get_main": 0x989BC0,
    "Camera_set_fieldOfView": 0x98A060,
    "RenderSettings_set_fog": 0x146A280,
    "Rigidbody_set_useGravity": 0x12D8160,
    "Rigidbody_set_detectCollisions": 0x12D8210,
    "Rigidbody_set_isKinematic": 0x12D8240,
    "Entity_GetPosition": 0x8D71C70,
    "Entity_SetPosition": 0xF42DAC0,
    "ReadSafeFloat": 0x12E9DE40,
    "DoHitEntity": 0x1086F500,
    "CalcDamage": 0x13C0EAD0,
    "Combat_SetHP": 0x1086C7E0,
    "VCHM_NotifyLandInner": 0xAC2F5C0,
    "OHCE_ModifySkillCdMul": 0x1346D710,
    "OHCE_SkillCdTick": 0x13467820,
    "SkillResetCd": 0xAD7FBC0,
    "PickupItem_TriggerPress": 0x10E0A660,
    "HumanoidMove_LateTick": 0x10976620,
    "EntityActor_GetPosX(ours)": 0x769D330,
    "MonoStaminaInfo_set_maxStamina(ours)": 0x10A8DE50,
    "VCHumanoidMove_JIDHLNCONOE(ours)": 0x9CB6230,
}

data = open(EXE, "rb").read()
pe = pefile.PE(data=data, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])


def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + rva - s.VirtualAddress
    return None


exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
fo = rva_to_off(exc.VirtualAddress)
starts = set()
for i in range(exc.Size // 12):
    b, e, u = struct.unpack_from("<III", data, fo + i * 12)
    if 0x1000 < b < 0xF0000000:
        starts.add(b)

print(f"{'name':44} {'rva':>10}  func  bytes")
print("-" * 100)
for name, rva in CANDIDATES.items():
    off = rva_to_off(rva)
    if off is None:
        print(f"{name:44} 0x{rva:08X}  NO-SECTION")
        continue
    b = data[off:off + 16]
    isfunc = rva in starts
    print(f"{name:44} 0x{rva:08X}  {'YES ' if isfunc else 'no  '}  {b.hex()}")
