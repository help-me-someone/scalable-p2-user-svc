# scalable-p2-gateway

This is responsible for acting as an interface into the microservice system.

This service is also bundled with the authentication service. This is useful since we can make sure that endpoints can enforce authorization.

Natively, this service exposes two different endpoints, namely `signin` and `register`. Any other request will be forwarded to their respective microservice.
