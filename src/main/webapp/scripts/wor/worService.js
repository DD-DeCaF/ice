angular.module('ice.wor.service', [])
    .factory('WebOfRegistries', function ($resource, $cookieStore) {
        return function () {
            return $resource('/rest/web', {partnerId:'@partnerId', url:'@url', entryId:'@entryId'}, {
                query:{
                    method:'GET',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                getPartner:{
                    method:'GET',
                    url:'/rest/web/partner/:partnerId',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                addPartner:{
                    method:'POST',
                    url:'/rest/web/partner',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                removePartner:{
                    method:'DELETE',
                    url:'/rest/web/partner/:url',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                updatePartner:{
                    method:'PUT',
                    url:'/rest/web/partner/:url',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                getPublicEntries:{
                    method:'GET',
                    url:'/rest/web/:partnerId/entries',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                },

                getPublicEntry:{
                    method:'GET',
                    url:'/rest/web/:partnerId/entries/:entryId',
                    responseType:'json',
                    headers:{'X-ICE-Authentication-SessionId':$cookieStore.get("sessionId")}
                }
            });
        }
    });