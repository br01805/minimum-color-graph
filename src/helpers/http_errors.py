from http import HTTPStatus
import helpers.quoted_storm_value as qsv

class HttpError(Exception):
    """This class is the base for all Synapse Connector endpoints to communicate failure/error conditions."""
    def __init__(self, rsp_code: HTTPStatus, status_msg: str, status_code: int):
        """Constructor to create new HTTP error object
        Args:
          rsp_code    The HTTP response codes
          status_msg  The error object status message
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__()
        assert isinstance(status_msg, str)
        self.rsp_code = rsp_code
        self.status_msg = status_msg
        self.status_code = status_code

    def __str__(self):
        return 'http_code={}, status_msg={}, status_code={}'.format(self.rsp_code, self.status_msg, self.status_code)

class ParameterError(HttpError):
    """This class reports parameter validation errors."""
    def __init__(self, names, message: str, status_code: int):
        """Constructor to create new Parameter error object
        Args:
          names (list) A list of parameters strings that are missing, have incorrect variable type, or value
                       is not correct
          message      The error object status message
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'parameter_error', status_code)
        self.names = names
        self.message = message

    def __str__(self):
        if self.names:
            return '{}: Invalid request parameters: {} [ID={}]'.format(self.names, self.message, self.status_code)
        return 'Invalid request parameters: {} [ID={}]'.format(self.message, self.status_code)


class UnregisteredTags(HttpError):
    """This class reports unregistered tags from apply/remove operation to a node.
    Tag names must be registered before they can be applied to a node."""
    def __init__(self, tags: list, status_code: int):
        """Constructor to create new UnregisteredTags error object
        Args:
          tags (list) A list of Synapse tag names
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'unregistered_tags', status_code)
        self.tags = tags

    def __str__(self):
        return 'Unregistered tags: {} [ID={}]'.format(self.tags, self.status_code)

class InvalidSynapseProperties(HttpError):
    """This class reports invalid Synapse properties used for SetProp operation. At this time,
     there is no way to determine which property name or value Synapse has rejected."""
    def __init__(self, property_names: list, status_code: int):
        """Constructor to create new InvalidSynapseProperties error object
        Args:
          property_names (list) A list of Set property names
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'invalid_synapse_properties', status_code)
        self.property_names = property_names

    def __str__(self):
        return 'Invalid Synapse property name or value: {} [ID={}]'.format(self.property_names, self.status_code)

class InvalidSynapseProperty(HttpError):
    """This class reports a single Synapse set property error that is triggered during an Add operation."""
    def __init__(self, synapse_error, status_code: int):
        """Constructor to create new InvalidSynapseProperty error object
        Args:
          synapse_error (str) The string value from the failed Synapse response string located in the 'oplog' property.
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'invalid_synapse_property', status_code)
        self.synapse_error = synapse_error

    def __str__(self):
        return 'Invalid Synapse property name or value: {} [ID={}]'.format(self.synapse_error, self.status_code)

class UnsupportedMethod(HttpError):
    """This class reports an unsupported method name for certain types of operations."""
    def __init__(self, method: str):
        """Constructor to create new HTTP error object
        Args:
          method   The HTTP method name
        """
        super().__init__(HTTPStatus.METHOD_NOT_ALLOWED, 'method_not_allowed', -1)
        self.method = method

    def __str__(self):
        return 'Unsupported method: {}'.format(self.method)


class InvalidEndpoint(HttpError):
    """This class reports an unregistered or invalid URL path."""
    def __init__(self, message: str):
        """Constructor to create new HTTP error object
        Args:
          message   A summary message of issue
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'invalid_endpoint', -1)
        self.message = message

    def __str__(self):
        return 'Invalid endpoint: {}'.format(self.message)

class ResourceExistsError(HttpError):
    """This class reports resource already exists (duplicate) condition. They may not be considered an error."""
    def __init__(self, name: str):
        """Constructor to create new HTTP error object
        Args:
          name    The resource name
        """
        super().__init__(HTTPStatus.CONFLICT, 'duplicate_resource', 1)
        assert name
        # Print the error string indicator in a form that is easier to understand
        if isinstance(name, tuple):
            name_new = qsv.parse(name[0], name[1])
        else:
            name_new = name
        self.name = name_new

    def __str__(self):
        return '{}: Already exists [ID={}]'.format(self.name, self.status_code)


class ResourceMissingError(HttpError):
    """This class reports resource or primary key does not exist error."""
    def __init__(self, name: str, status_code: int):
        """Constructor to create new HTTP error object
        Args:
          name        The resource name
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.GONE, 'missing_resource', status_code)
        assert name
        # Print the error string indicator in a form that is easier to understand
        if isinstance(name, tuple):
            name_new = qsv.parse(name[0], name[1])
        else:
            name_new = name
        self.name = name_new

    def __str__(self):
        return '{}: Does not exist [ID={}]'.format(self.name, self.status_code)


class ConstraintError(HttpError):
    """This class reports insert/delete errors where certain conditions cannot be met (ex: trying to delete a
     multi-level tag, but the key has children)."""
    def __init__(self, name: str, message: str, status_code: int):
        """Constructor to create new HTTP error object
        Args:
          name        The resource name
          message     A error message
          status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'operation_constraint', status_code)
        self.name = name
        self.message = message

    def __str__(self):
        return '{}: Operation constaint: {} [ID={}]'.format(self.name, self.message, self.status_code)


class RelationshipSynapseError(HttpError):
    """This class reports issues creating a relationship node most likely do caused by bad input."""
    def __init__(self, parent_tufo, child_tufo: str, status_code: int):
        """Constructor to create new HTTP error object
        Args:
          parent_tufo The parent tuple form to use for creating the relationship/link to the child vertex.
          child_tufo  The child tuple to link to parent
          status_code A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'relationship_failure', status_code)
        assert parent_tufo
        assert child_tufo
        self.parent_tufo = parent_tufo
        self.child_tufo = child_tufo

    def __str__(self):
        return 'Cannot create relationship: {}, {} [ID={}]'.format(self.parent_tufo, self.child_tufo, self.status_code)

class InsertSynapseFormError(HttpError):
    """This class reports issues creating a relationship node most likely do caused by bad input."""
    def __init__(self, name: str, status_code: int):
        """Constructor to create new Insert Synapse error object
        Args:
          name The name=value form that was attempted to be created
          status_code A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'insert_form_error', status_code)
        assert name
        self.name = name

    def __str__(self):
        return 'Invalid Synapse type=property: {} [ID={}]'.format(self.name, self.status_code)

class StixTranslationError(HttpError):
    """This class reports stix translation errors during translation."""
    def __init__(self, stix_error, status_code: int):
        """Constructor to create new Stix error object
        Args:
            stix_error (str) The string value from the failed stix translation response string.
            status_code  A negative error code can be used to trace back condition to code
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'stix_translation_error', status_code)
        self.stix_error = stix_error

    def __str__(self):
        return 'Invalid Stix Translation: {} [ID={}]'.format(self.stix_error, self.status_code)


class SynapseError(HttpError):
    """This class report 'err' object that appear in a Synapse 010 storm() response object."""
    def __init__(self, name, desc_obj, status_code: int):
        """Constructor to create new Synapse error object
        Args:
            name (str) The Synapse exception name such as NoSuchName
            desc_obj (dict) An exception specific object tailored to each 'name'
        """
        super().__init__(HTTPStatus.BAD_REQUEST, 'synapse_error', status_code)
        self.name = name
        self.desc_obj = desc_obj

    def __str__(self):
        mesg = ''
        if 'name' in self.desc_obj:
            mesg += self.desc_obj['name'] + ', '
        if 'mesg' in self.desc_obj:
            mesg += self.desc_obj['mesg'] + ', '
        mesg = mesg.rstrip(', ')
        if not mesg:
            mesg = str(self.desc_obj)
        return '{}: {} [ID={}]'.format(self.name, mesg, self.status_code)
