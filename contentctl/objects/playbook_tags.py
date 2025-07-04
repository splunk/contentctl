from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
import enum
from contentctl.objects.detection import Detection


class PlaybookProduct(str, enum.Enum):
    SPLUNK_SOAR = "Splunk SOAR"


class PlaybookUseCase(str, enum.Enum):
    COLLECTION = "Collection"
    ENDPOINT = "Endpoint"
    ENRICHMENT = "Enrichment"
    MALWARE = "Malware"
    PHISHING = "Phishing"
    RESPONSE = "Response"
    UTILITY = "Utility"


class PlaybookType(str, enum.Enum):
    INPUT = "Input"
    AUTOMATION = "Automation"


class VpeType(str, enum.Enum):
    MODERN = "Modern"
    CLASSIC = "Classic"


class DefendTechnique(str, enum.Enum):
    D3_AA = "D3-AA"
    D3_ABPI = "D3-ABPI"
    D3_ACA = "D3-ACA"
    D3_ACH = "D3-ACH"
    D3_AH = "D3-AH"
    D3_AI = "D3-AI"
    D3_AL = "D3-AL"
    D3_ALLM = "D3-ALLM"
    D3_AM = "D3-AM"
    D3_AMED = "D3-AMED"
    D3_ANAA = "D3-ANAA"
    D3_ANCI = "D3-ANCI"
    D3_ANET = "D3-ANET"
    D3_APA = "D3-APA"
    D3_APLM = "D3-APLM"
    D3_AVE = "D3-AVE"
    D3_AZET = "D3-AZET"
    D3_BA = "D3-BA"
    D3_BAN = "D3-BAN"
    D3_BDI = "D3-BDI"
    D3_BSE = "D3-BSE"
    D3_CA = "D3-CA"
    D3_CAA = "D3-CAA"
    D3_CBAN = "D3-CBAN"
    D3_CCSA = "D3-CCSA"
    D3_CE = "D3-CE"
    D3_CERO = "D3-CERO"
    D3_CF = "D3-CF"
    D3_CFC = "D3-CFC"
    D3_CH = "D3-CH"
    D3_CHN = "D3-CHN"
    D3_CI = "D3-CI"
    D3_CIA = "D3-CIA"
    D3_CM = "D3-CM"
    D3_CNE = "D3-CNE"
    D3_CNR = "D3-CNR"
    D3_CNS = "D3-CNS"
    D3_CP = "D3-CP"
    D3_CQ = "D3-CQ"
    D3_CR = "D3-CR"
    D3_CRO = "D3-CRO"
    D3_CS = "D3-CS"
    D3_CSPP = "D3-CSPP"
    D3_CTS = "D3-CTS"
    D3_CV = "D3-CV"
    D3_DA = "D3-DA"
    D3_DAM = "D3-DAM"
    D3_DCE = "D3-DCE"
    D3_DE = "D3-DE"
    D3_DEM = "D3-DEM"
    D3_DENCR = "D3-DENCR"
    D3_DF = "D3-DF"
    D3_DI = "D3-DI"
    D3_DKE = "D3-DKE"
    D3_DKF = "D3-DKF"
    D3_DKP = "D3-DKP"
    D3_DLIC = "D3-DLIC"
    D3_DNR = "D3-DNR"
    D3_DNRA = "D3-DNRA"
    D3_DNSAL = "D3-DNSAL"
    D3_DNSCE = "D3-DNSCE"
    D3_DNSDL = "D3-DNSDL"
    D3_DNSTA = "D3-DNSTA"
    D3_DO = "D3-DO"
    D3_DP = "D3-DP"
    D3_DPLM = "D3-DPLM"
    D3_DPR = "D3-DPR"
    D3_DQSA = "D3-DQSA"
    D3_DRT = "D3-DRT"
    D3_DST = "D3-DST"
    D3_DTP = "D3-DTP"
    D3_DUC = "D3-DUC"
    D3_EAL = "D3-EAL"
    D3_EBWSAM = "D3-EBWSAM"
    D3_EDL = "D3-EDL"
    D3_EF = "D3-EF"
    D3_EFA = "D3-EFA"
    D3_EHB = "D3-EHB"
    D3_EHPV = "D3-EHPV"
    D3_EI = "D3-EI"
    D3_ER = "D3-ER"
    D3_ET = "D3-ET"
    D3_FA = "D3-FA"
    D3_FAPA = "D3-FAPA"
    D3_FBA = "D3-FBA"
    D3_FC = "D3-FC"
    D3_FCA = "D3-FCA"
    D3_FCDC = "D3-FCDC"
    D3_FCOA = "D3-FCOA"
    D3_FCR = "D3-FCR"
    D3_FE = "D3-FE"
    D3_FEMC = "D3-FEMC"
    D3_FEV = "D3-FEV"
    D3_FFV = "D3-FFV"
    D3_FH = "D3-FH"
    D3_FHRA = "D3-FHRA"
    D3_FIM = "D3-FIM"
    D3_FISV = "D3-FISV"
    D3_FMBV = "D3-FMBV"
    D3_FMCV = "D3-FMCV"
    D3_FMVV = "D3-FMVV"
    D3_FRDDL = "D3-FRDDL"
    D3_FRIDL = "D3-FRIDL"
    D3_FV = "D3-FV"
    D3_HBPI = "D3-HBPI"
    D3_HCI = "D3-HCI"
    D3_HD = "D3-HD"
    D3_HDDL = "D3-HDDL"
    D3_HDL = "D3-HDL"
    D3_HR = "D3-HR"
    D3_HS = "D3-HS"
    D3_IAA = "D3-IAA"
    D3_IBCA = "D3-IBCA"
    D3_ID = "D3-ID"
    D3_IDA = "D3-IDA"
    D3_IHN = "D3-IHN"
    D3_IOPR = "D3-IOPR"
    D3_IPCTA = "D3-IPCTA"
    D3_IPRA = "D3-IPRA"
    D3_IRA = "D3-IRA"
    D3_IRV = "D3-IRV"
    D3_ISVA = "D3-ISVA"
    D3_ITF = "D3-ITF"
    D3_JFAPA = "D3-JFAPA"
    D3_KBPI = "D3-KBPI"
    D3_LAM = "D3-LAM"
    D3_LAMED = "D3-LAMED"
    D3_LFAM = "D3-LFAM"
    D3_LFP = "D3-LFP"
    D3_LLM = "D3-LLM"
    D3_MA = "D3-MA"
    D3_MAN = "D3-MAN"
    D3_MBSV = "D3-MBSV"
    D3_MBT = "D3-MBT"
    D3_MENCR = "D3-MENCR"
    D3_MFA = "D3-MFA"
    D3_MH = "D3-MH"
    D3_NAM = "D3-NAM"
    D3_NI = "D3-NI"
    D3_NM = "D3-NM"
    D3_NNI = "D3-NNI"
    D3_NPC = "D3-NPC"
    D3_NRAM = "D3-NRAM"
    D3_NTA = "D3-NTA"
    D3_NTCD = "D3-NTCD"
    D3_NTF = "D3-NTF"
    D3_NTPM = "D3-NTPM"
    D3_NTSA = "D3-NTSA"
    D3_NVA = "D3-NVA"
    D3_OAM = "D3-OAM"
    D3_ODM = "D3-ODM"
    D3_OE = "D3-OE"
    D3_OM = "D3-OM"
    D3_ORA = "D3-ORA"
    D3_OSM = "D3-OSM"
    D3_OTF = "D3-OTF"
    D3_OTP = "D3-OTP"
    D3_PA = "D3-PA"
    D3_PAM = "D3-PAM"
    D3_PAN = "D3-PAN"
    D3_PBWSAM = "D3-PBWSAM"
    D3_PCA = "D3-PCA"
    D3_PCSV = "D3-PCSV"
    D3_PE = "D3-PE"
    D3_PFV = "D3-PFV"
    D3_PH = "D3-PH"
    D3_PHDURA = "D3-PHDURA"
    D3_PLA = "D3-PLA"
    D3_PLLM = "D3-PLLM"
    D3_PLM = "D3-PLM"
    D3_PM = "D3-PM"
    D3_PMAD = "D3-PMAD"
    D3_PR = "D3-PR"
    D3_PS = "D3-PS"
    D3_PSA = "D3-PSA"
    D3_PSEP = "D3-PSEP"
    D3_PSMD = "D3-PSMD"
    D3_PT = "D3-PT"
    D3_PV = "D3-PV"
    D3_PWA = "D3-PWA"
    D3_RA = "D3-RA"
    D3_RAM = "D3-RAM"
    D3_RAPA = "D3-RAPA"
    D3_RC = "D3-RC"
    D3_RD = "D3-RD"
    D3_RDI = "D3-RDI"
    D3_RE = "D3-RE"
    D3_RF = "D3-RF"
    D3_RFAM = "D3-RFAM"
    D3_RFS = "D3-RFS"
    D3_RIC = "D3-RIC"
    D3_RKD = "D3-RKD"
    D3_RN = "D3-RN"
    D3_RNA = "D3-RNA"
    D3_RO = "D3-RO"
    D3_RPA = "D3-RPA"
    D3_RRID = "D3-RRID"
    D3_RS = "D3-RS"
    D3_RTA = "D3-RTA"
    D3_RTSD = "D3-RTSD"
    D3_RUAA = "D3-RUAA"
    D3_SAOR = "D3-SAOR"
    D3_SBV = "D3-SBV"
    D3_SCA = "D3-SCA"
    D3_SCF = "D3-SCF"
    D3_SCH = "D3-SCH"
    D3_SCP = "D3-SCP"
    D3_SDA = "D3-SDA"
    D3_SDM = "D3-SDM"
    D3_SEA = "D3-SEA"
    D3_SFA = "D3-SFA"
    D3_SFCV = "D3-SFCV"
    D3_SFV = "D3-SFV"
    D3_SHN = "D3-SHN"
    D3_SICA = "D3-SICA"
    D3_SJA = "D3-SJA"
    D3_SMRA = "D3-SMRA"
    D3_SPP = "D3-SPP"
    D3_SRA = "D3-SRA"
    D3_SSC = "D3-SSC"
    D3_ST = "D3-ST"
    D3_SU = "D3-SU"
    D3_SVCDM = "D3-SVCDM"
    D3_SWI = "D3-SWI"
    D3_SYSDM = "D3-SYSDM"
    D3_SYSM = "D3-SYSM"
    D3_SYSVA = "D3-SYSVA"
    D3_TAAN = "D3-TAAN"
    D3_TB = "D3-TB"
    D3_TBA = "D3-TBA"
    D3_TBI = "D3-TBI"
    D3_TL = "D3-TL"
    D3_UA = "D3-UA"
    D3_UAP = "D3-UAP"
    D3_UBA = "D3-UBA"
    D3_UDTA = "D3-UDTA"
    D3_UGLPA = "D3-UGLPA"
    D3_ULA = "D3-ULA"
    D3_URA = "D3-URA"
    D3_USICA = "D3-USICA"
    D3_VI = "D3-VI"
    D3_VTV = "D3-VTV"
    D3_WSAA = "D3-WSAA"
    D3_WSAM = "D3-WSAM"


class PlaybookTag(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analytic_story: Optional[list] = None
    detections: Optional[list] = None
    platform_tags: list[str] = Field(..., min_length=0)
    playbook_type: PlaybookType = Field(...)
    vpe_type: VpeType = Field(...)
    playbook_fields: list[str] = Field([], min_length=0)
    product: list[PlaybookProduct] = Field([], min_length=0)
    use_cases: list[PlaybookUseCase] = Field([], min_length=0)
    defend_technique_id: Optional[List[DefendTechnique]] = None

    labels: list[str] = []
    playbook_outputs: list[str] = []

    detection_objects: list[Detection] = []
