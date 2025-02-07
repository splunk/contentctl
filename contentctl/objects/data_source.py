from __future__ import annotations
from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from enum import StrEnum, auto


from pydantic import BaseModel, Field, HttpUrl, model_serializer, ConfigDict, computed_field
from functools import cached_property

from contentctl.objects.security_content_object import SecurityContentObject


class TA(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    url: HttpUrl 
    version: str


class DataSourceDataModel(StrEnum):
    ocsf = auto()
    custom_cim = auto()
    cim = auto()


class Field_Mapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data_model: DataSourceDataModel
    data_set: str | None = None
    mapping: dict[str, str]


class LogConvert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # This should really be a DataSource object, 
    # but the order in which they are defined makes 
    # this challenging. 
    # We will need to keep both these fields around for now
    data_source: str  
    _data_source_object: DataSource | None = None
    mapping: dict[str, str]

    @computed_field
    @cached_property    
    def data_source_object(self)->DataSource:
        if self._data_source_object is None:
            raise ValueError(f"Error - LogConvert.data_source object {self.data_source} "
                             "has not been resolved. Please ensure that 'configure_data_source_object' has been called")
        return self._data_source_object

    def resolveDataSourceObject(self, director: DirectorOutputDto | None )->None:
        self._data_source_object = DataSource.mapNamesToSecurityContentObjects([self.data_source], director)[0]
        

class DataSource(SecurityContentObject):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(...)
    sourcetype: str = Field(...)
    separator: None | str = None
    configuration: None | str = None
    supported_TA: list[TA]
    fields: list[str] = []
    field_mappings: list[Field_Mapping] = []
    convert_to_log_source: list[LogConvert] = []
    example_log: None | str = None
    output_fields: list[str] = []

    @model_serializer
    def serialize_model(self):
        # Call serializer for parent
        super_fields = super().serialize_model()

        # All fields custom to this model
        model: dict[str, Any] = {
            "source": self.source,
            "sourcetype": self.sourcetype,
            "separator": self.separator,
            "configuration": self.configuration,
            "supported_TA": self.supported_TA,
            "fields": self.fields,
            "field_mappings": self.field_mappings,
            "convert_to_log_source": self.convert_to_log_source,
            "example_log": self.example_log,
        }

        # Combine fields from this model with fields from parent
        super_fields.update(model)

        # return the model
        return super_fields

    def resolveDataSourceObject(self, director: DirectorOutputDto | None )->None:
        for index,log in enumerate(self.convert_to_log_source):
            try:
                log.resolveDataSourceObject(director)
            except Exception as e:
                raise ValueError(f"Error encountered when resolving field 'convert_to_log_source[{index}].data_source: {log.data_source}'. No DataSource by the name '{log.data_source}' exists")