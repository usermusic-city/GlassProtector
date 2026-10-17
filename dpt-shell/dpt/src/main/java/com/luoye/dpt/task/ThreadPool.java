package com.luoye.dpt.task;

import com.luoye.dpt.config.Const;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * @author luoyesiqiu
 */
public class ThreadPool {
    private static final int CORE_POOL_SIZE = 2;
    private static final int MAX_POOL_SIZE = Math.max(CORE_POOL_SIZE, Runtime.getRuntime().availableProcessors());

    private static final ThreadPool sInst = new ThreadPool();
    private static final ThreadPoolExecutor sThreadPoolExecutor = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(),
            new CustomThreadFactory());
    private ThreadPool(){

    }
    public static ThreadPool getInstance() {
        return sInst;
    }

    public static class CustomThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r);
            t.setName(Const.DEFAULT_THREAD_NAME + "-" + t.getId());
            return t;
        }
    }

    public void execute(Runnable task){
        sThreadPoolExecutor.execute(task);
    }

    public void shutdown(){
        sThreadPoolExecutor.shutdown();
    }
}
