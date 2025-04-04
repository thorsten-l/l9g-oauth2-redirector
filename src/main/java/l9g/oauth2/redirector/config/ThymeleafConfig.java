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
package l9g.oauth2.redirector.config;

import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.IEngineConfiguration;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Configuration
@Slf4j
public class ThymeleafConfig
{
  @Bean
  public SpringResourceTemplateResolver customTemplateResolver()
  {
    log.debug("customTemplateResolver");

    SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver()
    {
      @Override
      protected String computeResourceName(IEngineConfiguration configuration, 
        String ownerTemplate, String template, String prefix, String suffix, 
        boolean forceSuffix, Map<String, String> templateAliases, 
        Map<String, Object> templateResolutionAttributes)
      {
        template = template.substring(2);
        
        return super.computeResourceName(configuration, ownerTemplate, 
          template, prefix, suffix, forceSuffix, templateAliases, 
          templateResolutionAttributes);
      }

    };
    resolver.setPrefix("file:./templates/");
    resolver.setSuffix(".html");
    resolver.setTemplateMode("HTML");
    resolver.setCharacterEncoding("UTF-8");
    resolver.setOrder(1);
    resolver.setCheckExistence(true);
    resolver.setResolvablePatterns(java.util.Collections.singleton("r/*"));
    return resolver;
  }

}
