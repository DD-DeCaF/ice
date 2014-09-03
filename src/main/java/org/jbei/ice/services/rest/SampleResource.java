package org.jbei.ice.services.rest;

import java.util.ArrayList;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.jbei.ice.lib.common.logging.Logger;
import org.jbei.ice.lib.dto.sample.SampleRequest;
import org.jbei.ice.lib.entry.sample.SampleRequests;

/**
 * @author Hector Plahar
 */
@Path("/samples")
public class SampleResource extends RestResource {

    private SampleRequests sampleRequests = new SampleRequests();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/requests")
    public ArrayList<SampleRequest> getRequests(
            @HeaderParam(value = "X-ICE-Authentication-SessionId") String userAgentHeader) {
        String userId = getUserIdFromSessionHeader(userAgentHeader);
        Logger.info(userId + ": retrieving all sample requests");
        return sampleRequests.getPendingRequests(userId);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/requests/:userId")
    public ArrayList<SampleRequest> getUserRequests(
            @HeaderParam(value = "X-ICE-Authentication-SessionId") String userAgentHeader,
            @QueryParam("status") String status) {
        String userId = getUserIdFromSessionHeader(userAgentHeader);
        Logger.info(userId + ": retrieving sample requests for user");
        return sampleRequests.getPendingRequests(userId);
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/requests")
    public ArrayList<SampleRequest> addRequest(
            @HeaderParam(value = "X-ICE-Authentication-SessionId") String userAgentHeader,
            SampleRequest request) {
        String userId = getUserIdFromSessionHeader(userAgentHeader);
        Logger.info(userId + ": add sample request to cart for " + request.getPartData().getId());
        return sampleRequests.placeSampleInCart(userId, request);
    }

//    @GET
//    @Produces(MediaType.APPLICATION_JSON)
//    public ArrayList<Sam> get(
//            @HeaderParam(value = "X-ICE-Authentication-SessionId") String userAgentHeader) {
//        try {
//            HibernateUtil.beginTransaction();
//            String userId = getUserIdFromSessionHeader(userAgentHeader);
//            Logger.info(userId + ": retrieving available accounts for group creation");
//            GroupController controller = new GroupController();
//            return controller.getAvailableAccounts(userId);
//        } finally {
//            HibernateUtil.commitTransaction();
//        }
//    }
}