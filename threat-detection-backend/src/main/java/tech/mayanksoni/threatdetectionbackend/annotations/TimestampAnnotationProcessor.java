package tech.mayanksoni.threatdetectionbackend.annotations;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;
import java.util.Set;

@SupportedSourceVersion(SourceVersion.RELEASE_21)
@SupportedAnnotationTypes({
        "tech.mayanksoni.threatdetectionbackend.annotations.CreationTimestamp",
        "tech.mayanksoni.threatdetectionbackend.annotations.UpdateTimestamp"
})
public class TimestampAnnotationProcessor extends AbstractProcessor {
    private Types typeUtils;
    private Elements elementUtils;
    @Override
    public synchronized void init(ProcessingEnvironment processingEnvironment){
        super.init(processingEnvironment);
        this.typeUtils = processingEnvironment.getTypeUtils();
        this.elementUtils = processingEnvironment.getElementUtils();
    }
    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (TypeElement annotation : annotations) {
            for (Element element : roundEnv.getElementsAnnotatedWith(annotation)) {
                if (element.getKind() != ElementKind.FIELD) {
                    processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR,
                            "@CreationTimestamp and @UpdateTimestamp can only be applied to fields", element);
                    continue;
                }

                TypeMirror fieldType = element.asType();
                if (!isValidType(fieldType)) {
                    processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR,
                            "Fields annotated with @CreationTimestamp or @UpdateTimestamp must be of type Instant, ZonedDateTime, or LocalDateTime", element);
                }
            }
        }
        return true;
    }
    private boolean isValidType(TypeMirror fieldType) {
        TypeMirror instantType = elementUtils.getTypeElement("java.time.Instant").asType();
        TypeMirror zonedDateTimeType = elementUtils.getTypeElement("java.time.ZonedDateTime").asType();
        TypeMirror localDateTimeType = elementUtils.getTypeElement("java.time.LocalDateTime").asType();
        return
                typeUtils.isSameType(fieldType, instantType) || typeUtils.isSameType(fieldType, zonedDateTimeType) || typeUtils.isSameType(fieldType, localDateTimeType);
    }

}
