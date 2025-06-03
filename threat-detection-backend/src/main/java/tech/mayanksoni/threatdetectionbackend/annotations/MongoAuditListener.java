package tech.mayanksoni.threatdetectionbackend.annotations;

import com.mongodb.lang.NonNull;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertCallback;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.time.Instant;

@Component
public class MongoAuditListener<T> implements BeforeConvertCallback<T> {
    @Override
    public @NonNull T onBeforeConvert(@NonNull T entity,@NonNull String collection) {
        try{
            for(Field field: entity.getClass().getDeclaredFields()) {
                field.setAccessible(true);
                if(field.isAnnotationPresent(CreationTimestamp.class) && field.get(entity) == null){
                    field.set(entity, Instant.now());
                }
                if(field.isAnnotationPresent(UpdateTimestamp.class)){
                    field.set(entity, Instant.now());
                }
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Failed to set audit timestamp fields: " + e.getMessage(), e);
        }
        return entity;
    }
}
