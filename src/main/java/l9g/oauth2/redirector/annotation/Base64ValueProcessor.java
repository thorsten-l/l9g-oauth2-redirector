/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package l9g.oauth2.redirector.annotation;

import java.lang.reflect.Field;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.ReflectionUtils;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class Base64ValueProcessor implements BeanPostProcessor
{
  private final Environment environment;

  @Override
  public Object postProcessBeforeInitialization(Object bean, String beanName)
    throws BeansException
  {
    Field[] fields = bean.getClass().getDeclaredFields();

    for(Field field : fields)
    {
      Base64Value annotation = field.getAnnotation(Base64Value.class);
      if(annotation != null)
      {
        String environmentName = annotation.value()
          .replaceAll("^\\$\\{", "").replaceAll("}$", "");

        String[] nameAndDefaultValue = environmentName.split("\\:");

        String encryptedValue = (nameAndDefaultValue.length == 1)
          ? environment.getProperty(environmentName)
          : environment.getProperty(nameAndDefaultValue[0]);

        byte[] value = null;
        
        try
        {
          value = (encryptedValue != null)
            ? Base64.getDecoder().decode(encryptedValue)
            : null;
        }
        catch(Throwable t)
        {
          // do nothing
        }
        
        field.setAccessible(true);
        ReflectionUtils.setField(field, bean, value);
      }
    }
    return bean;
  }

}
