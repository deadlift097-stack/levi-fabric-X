package com.example.hello;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
public class HelloMod implements ModInitializer {
  public static final Logger LOGGER = LoggerFactory.getLogger("hello");
  public static boolean greetEnabled = true;
  public static int greetCount = 3;
  public static String greeting = "Hi there";
  @Override public void onInitialize() {
    LOGGER.info("Hello Fabric world!");
    LOGGER.info("Greeting is {}", greeting);
    ServerLifecycleEvents.SERVER_STARTED.register(s -> LOGGER.info("Server started, count {}", greetCount));
    ServerLifecycleEvents.SERVER_STOPPING.register(s -> LOGGER.warn("Bye"));
    new Thread(() -> {}).start();
    for (int i=0;i<2;i++) LOGGER.info("loop");
  }
}
