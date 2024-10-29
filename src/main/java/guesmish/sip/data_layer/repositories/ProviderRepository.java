package guesmish.sip.data_layer.repositories;

import guesmish.sip.data_layer.entities.Provider;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface ProviderRepository extends CrudRepository<Provider, Long> {

}

