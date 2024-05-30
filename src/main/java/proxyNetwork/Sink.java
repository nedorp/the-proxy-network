package proxyNetwork;


import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static proxyNetwork.PNMessage.getBatchOfMessagesPNMessage;

/**
 * This module collects all the sinkInfo arriving from various clients
 * Correlation-Based Traffic Analysis Atacks on
 * Anonymity Networks
 * Ye Zhu - Cleveland State University, y.zhu61@csuohio.edu
 * Xinwen Fu - Dakota State University, xinwen.fu@dsu.edu
 * Byran Gramham - Texas A & M International University, bgraham@tamu.edu
 * Riccardo Betati - Texas A & M University - College Station, betati@cs.tamu.ed
 *
 * Batch Strategy s3 Threshold or Timed Mix:
 * if timer times out, send n packets; else if m = n, send n packet and reset timer
 *
 */
public class Sink {

    // Messages are delayed in forwarding for at max 2 seconds?
    private static final long MAX_HOLD_MESSAGE_PERIOD = 20000;
    private static final int BATCH_SIZE = 4;
    private InetAddress myAddress;

    private class SinkInfo {

        // Used as lock for flush function (reach of batch) and periodic flush
        Lock lock;

        Instant lastSinkFlush;
        ConcurrentLinkedQueue<RouteStepChunk> messages;

        // TODO Dare un TTL a questi oggetti
        private SinkInfo(){

            lastSinkFlush = Instant.now();
            messages = new ConcurrentLinkedQueue<>();
            lock = new ReentrantLock();
        }
    }

    private ConcurrentHashMap<String, SinkInfo> sinkInfo;

    /**
     * When count reaches batch size, it flushes the batch of sinkInfo
     */
    public Sink(InetAddress myAddress){

        this.myAddress = myAddress;
        this.sinkInfo = new ConcurrentHashMap<>();

        periodicEmptySink.start();

    }

    /**
     * Shuffle sinkInfo to try to avoid control by an adversary who control both Proxies and Receiver.
     * Introduce several jumps with key so it's harder to control many machines.
     * @param routeStepChunks messages
     */
    private List<RouteStepChunk> shuffle(List<RouteStepChunk> routeStepChunks){

        try {

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            // Shuffle sinkInfo
            Collections.shuffle(routeStepChunks, random);

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return routeStepChunks;

    }

    /**
     * Flush Messages for the next node
     * @param IP
     */
    private void flush(String IP) {

        ConcurrentLinkedQueue<RouteStepChunk> routeStepChunks = sinkInfo.get(IP).messages;

        Lock lock = sinkInfo.get(IP).lock;
        if (lock.tryLock()) {

            try {

                // Extract messages from the queue
                List<RouteStepChunk> toBeFlushed = extractData(routeStepChunks);

                // Shuffle Messages. Why twice? FIXME
                toBeFlushed = shuffle(toBeFlushed);

                emptySink(IP, toBeFlushed);
                sinkInfo.remove(IP);

            } finally {
                lock.unlock();
            }
        }

    }

    private LinkedList<RouteStepChunk> extractData(ConcurrentLinkedQueue<RouteStepChunk> routeStepChunks) {

        LinkedList<RouteStepChunk> returnedList = new LinkedList<>();
        int size = routeStepChunks.size();
        for (int i = 0; i < size; i++) {
            RouteStepChunk poll = routeStepChunks.poll();
            returnedList.add(poll);
        }
        return returnedList;

    }

    private void emptySink(String IP, List<RouteStepChunk> messages) {

        HashMap<Integer, List<RouteStepChunk>> messagesByPort = new HashMap<>();

        // Create a map with port and map of messages
        messages.forEach((chunkRoute -> {

            messagesByPort.computeIfAbsent(chunkRoute.getPort(), k -> new LinkedList<>());
            messagesByPort.compute(chunkRoute.getPort(), (a, list) -> {
                list.add(chunkRoute);
                return list;
            });


        }));

        // Inoltra correttamente alla porta giusta
        messagesByPort.forEach((port, msgs) -> {

            try {

                Socket toForwardSocket = new Socket(IP, port, this.myAddress, 0);

                if (toForwardSocket.isConnected()) {

                    // Send to other proxy
                    ObjectOutputStream toBrotherOut = new ObjectOutputStream(toForwardSocket.getOutputStream());

                    PNMessage batchOfMessagesPNMessage = getBatchOfMessagesPNMessage(msgs);
                    toBrotherOut.writeObject(batchOfMessagesPNMessage);
                }

                else {
                    System.out.println("Not Connected!");
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

        });

    }

    public void receiveMessage(RouteStepChunk incomingMessage){

        String ip = incomingMessage.getIP();
        SinkInfo ipInfo = this.sinkInfo.computeIfAbsent(ip, k -> new SinkInfo());

        ConcurrentLinkedQueue<RouteStepChunk> routeStepChunks = ipInfo.messages;

        // Update the chunkroute list
        routeStepChunks.add(incomingMessage);

        if(isBatchFull(routeStepChunks.size())){
            flush(ip);
        }

    }

    private boolean isBatchFull(Integer size) {
        return size == BATCH_SIZE;
    }

    private Thread periodicEmptySink = new Thread(() -> {

        while(true) {

            // Choose Timeout
            long timeout = Math.round(Math.random() * MAX_HOLD_MESSAGE_PERIOD);
            try {
                Thread.sleep(timeout);

                System.out.println(this.myAddress.toString() + " Batching messages...");
                flushAll();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }


        }


    });

    private void flushAll() {
        sinkInfo.forEach((ip, sinkInfo) -> {
            flush(ip);
        });
    }


}
