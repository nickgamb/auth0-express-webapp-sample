function deleteUserSessions(sessionStore, userId, sid) {
    sessionStore.all((error, sessions) => {
      
      // loop over all existing sessions
      for (const [sessionId, session] of Object.entries(sessions)) {
        
        // logout token contains sid
        if (sid) {
          
          // session has same sid as the logout token 
          // AND (session user id is the same as in the logout token
          //      OR the logout token does not contain a userId)
          if (
            sid === session.data.sid &&
            (session.data.user_id === userId || !userId)
          ) {
            console.log(
              `Deleting session id: ${sessionId} with sid: ${sid} for userId: ${userId}`
            );
            deleteSession(sessionId);
          }
          
        // logout token does not contain sid
        } else {
          // session user id is the same as in the logout token
          if (session.data.user_id === userId) {
            console.log(
              `Deleting session id: ${sessionId} for userId: ${userId}`
            );
            deleteSession(sessionId);
          }
        }
      }
    });
  }
  
  function deleteSession(sessionId) {
    sessionStore.destroy(sessionId, (error) => {
      if (error) {
        console.log(error);
      }
    });
  }
  
  module.exports = deleteUserSessions;
  