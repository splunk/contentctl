from pydantic import BaseModel


class RiskObject(BaseModel):
    """Representation of a risk object associated with a risk analysis action

    Detections define observables (e.g. a user) with a role of "victim" with which the risk analysis and scoring gets
    associated. On the Enterprise Security side, these translate to risk objects. Each risk object has a field from
    which it draws its name and a type (e.g. user, system, etc.). A risk event will be generated for each risk
    object accordingly. NOTE: obervables w/out an explicit role MAY default to being a risk object; it is not clear
    at the time of writing
    :param field: the name of the field from which the risk object will get it's name
    :param type_: the type of the risk object (e.g. "system")
    :param score: the risk score associated with the obersevable (e.g. 64)
    """
    field: str
    type: str
    score: int
