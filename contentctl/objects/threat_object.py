from pydantic import BaseModel


class ThreatObject(BaseModel):
    """Representation of a threat object associated with a risk analysis action

    Detections define observables with a role of "attacker" with which the risk analysis gets associated. On the
    Enterprise Security side, these translate to threat objects. Each threat object has a field from which it draws its
    name and a type. NOTE: it is unclear whether a threat object will have a corresponding risk event, or perhaps a
    corresponding threat event?
    :param field: the name of the field from which the risk object will get it's name
    :param type_: the type of the risk object (e.g. "system")
    """
    field: str
    type: str
