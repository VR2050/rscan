package org.webrtc.mozi;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes3.dex */
public class LeakMonitor {
    private static final String TAG = "LeakMonitor";
    private static boolean sEnabled;
    private static LeakingHandler sLeakingHandler;
    private static Map<String, Resource> sResources = new ConcurrentHashMap();
    private static Executor sExecutor = new Executor() { // from class: org.webrtc.mozi.LeakMonitor.1
        @Override // java.util.concurrent.Executor
        public void execute(Runnable command) {
            if (command != null) {
                command.run();
            }
        }
    };

    public interface LeakingHandler {
        void onLeaking(Resource resource);

        void onOverflow(Resource resource);
    }

    public static class Resource {
        Map<String, AtomicInteger> allocationCounters = new HashMap();
        AtomicInteger counter = new AtomicInteger();
        AtomicBoolean leaked = new AtomicBoolean();
        int leakingThreshold;
        int overflowThreshold;
        String type;

        Resource(String type) {
            this.type = type;
        }

        void setOverflowThreshold(int threshold) {
            this.overflowThreshold = threshold;
        }

        public void setLeakingThreshold(int leakingThreshold) {
            this.leakingThreshold = leakingThreshold;
        }

        public int getLeakingThreshold() {
            return this.leakingThreshold;
        }

        public int getOverflowThreshold() {
            return this.overflowThreshold;
        }

        boolean isLeaked() {
            return this.leaked.get();
        }

        void allocate(String allocation) {
            if (allocation != null) {
                AtomicInteger allocator = this.allocationCounters.get(allocation);
                if (allocator == null) {
                    allocator = new AtomicInteger();
                    this.allocationCounters.put(allocation, allocator);
                }
                allocator.incrementAndGet();
            }
            int count = this.counter.incrementAndGet();
            int i = this.overflowThreshold;
            if (i > 0 && count > i) {
                LeakMonitor.onOverflow(this);
            }
        }

        public String getAllocationMap() {
            StringBuilder sb = new StringBuilder("Resource  ");
            sb.append(this.type);
            sb.append(", allocations: ");
            for (Map.Entry<String, AtomicInteger> entry : this.allocationCounters.entrySet()) {
                sb.append(entry.getKey());
                sb.append(" = ");
                sb.append(entry.getValue().get());
                sb.append(", ");
            }
            return sb.toString();
        }

        void deallocate(String allocation) {
            AtomicInteger allocator;
            if (allocation != null && (allocator = this.allocationCounters.get(allocation)) != null) {
                allocator.decrementAndGet();
            }
            this.counter.decrementAndGet();
        }

        public int count() {
            return count(null);
        }

        public int count(String allocation) {
            if (allocation != null) {
                AtomicInteger allocator = this.allocationCounters.get(allocation);
                if (allocator == null) {
                    return 0;
                }
                return allocator.get();
            }
            return this.counter.get();
        }

        public String getType() {
            return this.type;
        }
    }

    static void onOverflow(Resource resource) {
        LeakingHandler handler = sLeakingHandler;
        if (handler != null) {
            handler.onOverflow(resource);
        }
    }

    static void onLeaking(Resource resource) {
        LeakingHandler handler = sLeakingHandler;
        if (handler != null) {
            handler.onLeaking(resource);
        }
    }

    public static int getCount(String type) {
        return getCount(type, null);
    }

    public static int getCount(String type, String allocation) {
        Resource resource = sResources.get(type);
        if (resource == null) {
            return 0;
        }
        return resource.count(allocation);
    }

    public static boolean isLeaked(String type) {
        Resource resource = sResources.get(type);
        return resource != null && resource.isLeaked();
    }

    public static void allocate(String type) {
        allocate(type, null);
    }

    public static void allocate(final String type, final String allocation) {
        if (!sEnabled) {
            return;
        }
        sExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.LeakMonitor.2
            @Override // java.lang.Runnable
            public void run() {
                Resource resource = (Resource) LeakMonitor.sResources.get(type);
                if (resource == null) {
                    resource = new Resource(type);
                    LeakMonitor.sResources.put(type, resource);
                }
                resource.allocate(allocation);
            }
        });
    }

    public static void deallocate(String type) {
        deallocate(type, null);
    }

    public static void deallocate(final String type, final String allocation) {
        if (!sEnabled) {
            return;
        }
        sExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.LeakMonitor.3
            @Override // java.lang.Runnable
            public void run() {
                Resource resource = (Resource) LeakMonitor.sResources.get(type);
                if (resource != null) {
                    resource.deallocate(allocation);
                }
            }
        });
    }

    public static void reset() {
        if (!sEnabled) {
            return;
        }
        sResources.clear();
    }

    public static void setLeakingHandler(LeakingHandler handler) {
        sLeakingHandler = handler;
    }

    public static void setOverflowThreshold(String type, int threshold) {
        setOverflowAndLeakingThreshold(type, threshold, 0);
    }

    public static void setOverflowAndLeakingThreshold(final String type, final int overflowThreshold, final int leakingThreshold) {
        if (!sEnabled) {
            return;
        }
        sExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.LeakMonitor.4
            @Override // java.lang.Runnable
            public void run() {
                Resource resource = (Resource) LeakMonitor.sResources.get(type);
                if (resource == null) {
                    resource = new Resource(type);
                    LeakMonitor.sResources.put(type, resource);
                }
                resource.setOverflowThreshold(overflowThreshold);
                resource.setLeakingThreshold(leakingThreshold);
            }
        });
    }

    public static void checkLeaking() {
        if (!sEnabled) {
            return;
        }
        sExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.LeakMonitor.5
            @Override // java.lang.Runnable
            public void run() {
                for (Resource resource : LeakMonitor.sResources.values()) {
                    if (resource.count() > resource.getLeakingThreshold()) {
                        resource.leaked.set(true);
                        LeakMonitor.onLeaking(resource);
                    } else {
                        resource.leaked.set(false);
                    }
                }
            }
        });
    }

    public static void setEnabled(boolean enabled) {
        sEnabled = enabled;
    }

    public static boolean isEnabled() {
        return sEnabled;
    }

    public static void setExecutor(Executor executor) {
        if (executor != null) {
            sExecutor = executor;
        }
    }
}
