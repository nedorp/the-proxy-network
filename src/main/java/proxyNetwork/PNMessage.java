package proxyNetwork;

import java.io.Serializable;
import java.util.List;

/**
 * Proxy Network Message Format
 */
public class PNMessage implements Serializable {

    static final long serialVersionUID = 0L;

    /** Message Code */
    private PNCodes messageCode;

    /** Used by the client to the first relay and in Non-Garlic Mode */
    RouteStepChunk singleRouteStepChunk;

    /** Used in Garlic Mode */
    List<RouteStepChunk> batchOfMessages;

    public boolean isABatch() {
        return messageCode == PNCodes.BATCH_OF_MESSAGES;
    }

    public static PNMessage getSingleChunkRouteMessage(RouteStepChunk wrappedMessage) {

        PNMessage pnMessage = new PNMessage();
        pnMessage.messageCode = PNCodes.SINGLE_MESSAGE;
        pnMessage.singleRouteStepChunk = wrappedMessage;
        return pnMessage;

    }

    public static PNMessage getBatchOfMessagesPNMessage(List<RouteStepChunk> messages) {

        PNMessage pnMessage = new PNMessage();
        pnMessage.messageCode = PNCodes.BATCH_OF_MESSAGES;
        pnMessage.batchOfMessages = messages;
        return pnMessage;


    }

    // Used by the receiver lib endpoint
    public RouteStepChunk getSingleMessage(){
        return singleRouteStepChunk;
    }

    public List<RouteStepChunk> getBatchOfMessages() {
        return batchOfMessages;
    }
}

enum PNCodes {

    SINGLE_MESSAGE,
    BATCH_OF_MESSAGES
}
