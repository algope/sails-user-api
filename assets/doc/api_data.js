define({ "api": [
  {
    "type": "get",
    "url": "/pay/getToken/",
    "title": "Get BrainTree Session Token",
    "name": "getToken",
    "group": "Payment",
    "version": "0.1.0",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "Token.",
            "description": ""
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "{\n \"token\": \"eyJ2ZXJzaW9uIjoyLCJhdXRob3JpemF0aW9uRmluZ2VycHJpbnQiOiI5ZWMyZmU4Yzg2YjNlNzRkNGNlNDZkNzFhMWE2NmU0MzM4NzBlODM2MzdlNzIyZDEyZGMyYTA2ZjI1NzczOWVifGNyZWF0ZWRfYXQ9MjAxNS0wOC0xOVQxODoyNDowMy4wMTM4NjIzNDkrMDAwMFx1MDAyNm1lcmNoYW50X2lkPTRxbjg0ZzZycmhtd2h6cmdcdTAwMjZwdWJsaWNfa2V5PXNmeXZyczVrYnJmNDZ2emsiLCJjb25maWdVcmwiOiJodHRwczovL2FwaS5zYW5kYm94LmJyYWludHJlZWdhdGV3YXkuY29tOjQ0My9tZXJjaGFudHMvNHFuODRnNnJyaG13aHpyZy9jbGllbnRfYXBpL3YxL2NvbmZpZ3VyYXRpb24iLCJjaGFsbGVuZ2VzIjpbXSwiZW52aXJvbm1lbnQiOiJzYW5kYm94IiwiY2xpZW50QXBpVXJsIjoiaHR0cHM6Ly9hcGkuc2FuZGJveC5icmFpbnRyZWVnYXRld2F5LmNvbTo0NDMvbWVyY2hhbnRzLzRxbjg0ZzZycmhtd2h6cmcvY2xpZW50X2FwaSIsImFzc2V0c1VybCI6Imh0dHBzOi8vYXNzZXRzLmJyYWludHJlZWdhdGV3YXkuY29tIiwiYXV0aFVybCI6Imh0dHBzOi8vYXV0aC52ZW5tby5zYW5kYm94LmJyYWludHJlZWdhdGV3YXkuY29tIiwiYW5hbHl0aWNzIjp7InVybCI6Imh0dHBzOi8vY2xpZW50LWFuYWx5dGljcy5zYW5kYm94LmJyYWludHJlZWdhdGV3YXkuY29tIn0sInRocmVlRFNlY3VyZUVuYWJsZWQiOmZhbHNlLCJwYXlwYWxFbmFibGVkIjp0cnVlLCJwYXlwYWwiOnsiZGlzcGxheU5hbWUiOiJNYXRlIEFwcCIsImNsaWVudElkIjpudWxsLCJwcml2YWN5VXJsIjoiaHR0cDovL2V4YW1wbGUuY29tL3BwIiwidXNlckFncmVlbWVudFVybCI6Imh0dHA6Ly9leGFtcGxlLmNvbS90b3MiLCJiYXNlVXJsIjoiaHR0cHM6Ly9hc3NldHMuYnJhaW50cmVlZ2F0ZXdheS5jb20iLCJhc3NldHNVcmwiOiJodHRwczovL2NoZWNrb3V0LnBheXBhbC5jb20iLCJkaXJlY3RCYXNlVXJsIjpudWxsLCJhbGxvd0h0dHAiOnRydWUsImVudmlyb25tZW50Tm9OZXR3b3JrIjp0cnVlLCJlbnZpcm9ubWVudCI6Im9mZmxpbmUiLCJ1bnZldHRlZE1lcmNoYW50IjpmYWxzZSwiYnJhaW50cmVlQ2xpZW50SWQiOiJtYXN0ZXJjbGllbnQzIiwiYmlsbGluZ0FncmVlbWVudHNFbmFibGVkIjpmYWxzZSwibWVyY2hhbnRBY2NvdW50SWQiOiJtYXRlYXBwIiwiY3VycmVuY3lJc29Db2RlIjoiVVNEIn0sImNvaW5iYXNlRW5hYmxlZCI6ZmFsc2UsIm1lcmNoYW50SWQiOiI0cW44NGc2cnJobXdoenJnIiwidmVubW8iOiJvZmYifQ==\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/PayController.js",
    "groupTitle": "Payment"
  },
  {
    "type": "get",
    "url": "/pay/pay/",
    "title": "Pay",
    "name": "pay",
    "group": "Payment",
    "version": "0.1.0",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "amount",
            "description": "<p>Amount of the payment.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "Token.",
            "description": ""
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "{\n \"BrainTreeTransactionSuccess\": \"false\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/PayController.js",
    "groupTitle": "Payment"
  },
  {
    "type": "post",
    "url": "/user/create/",
    "title": "Creates a user",
    "version": "0.1.0",
    "name": "CreateUser",
    "group": "User",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Email</p> ",
            "optional": false,
            "field": "email",
            "description": "<p>Mandatory Email of the user.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "password",
            "description": "<p>Mandatory Password of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "confirmPassword",
            "description": "<p>Mandatory Password confirmation of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "first_name",
            "description": "<p>Optional First Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "middle_name",
            "description": "<p>Optional Middle Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "last_name",
            "description": "<p>Optional Last Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "birthday",
            "description": "<p>Optional Birthday of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "phone",
            "description": "<p>Optional Phone of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "weight",
            "description": "<p>Optional Weight of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "height",
            "description": "<p>Optional Height of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "relationship",
            "description": "<p>Optional Relationship of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "sex",
            "description": "<p>Optional Sex of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "safeSex",
            "description": "<p>Optional Safe Sex of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "areYouOut",
            "description": "<p>Optional Are You Out Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "endownment",
            "description": "<p>Optional Endowment of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "sizeMatter",
            "description": "<p>Optional Size Matter of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "circumcisionPref",
            "description": "<p>Optional Circumcision Preference of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "circumcision",
            "description": "<p>Optional Circumcision Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "hairStyle",
            "description": "<p>Optional Hair Style of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "hairColor",
            "description": "<p>Optional Hair Color of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "facialHair",
            "description": "<p>Optional Facial Hair of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "tattoos",
            "description": "<p>Optional Tattoos of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "piercing",
            "description": "<p>Optional Piercing of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "smoke",
            "description": "<p>Optional Smoke Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "mood",
            "description": "<p>Optional Mood of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "aboutMyself",
            "description": "<p>Optional About Myself Description of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "aboutDescription",
            "description": "<p>Optional Description of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "bodyHair",
            "description": "<p>Optional Body Hair of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "ethnicity",
            "description": "<p>Optional Ethnicity of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "sexInterest",
            "description": "<p>Optional Sex Interest of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "lookingFor",
            "description": "<p>Optional Looking For Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "role",
            "description": "<p>Optional Role of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "fetish",
            "description": "<p>Optional Fetish of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "fun",
            "description": "<p>Optional Fun of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "sexualIdentification",
            "description": "<p>Optional Sexual Identification of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Boolean</p> ",
            "optional": false,
            "field": "isLogged",
            "description": "<p>Mandatory Online Status of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Profile",
            "description": "<ul> <li>Token.</li> </ul> "
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n \"user\": {\n     \"email\": \"test@test.com\",\n     \"createdAt\": \"2015-08-18T18:05:50.344Z\",\n     \"updatedAt\": \"2015-08-18T18:05:50.344Z\",\n     \"user_id\": 5\n },\n \"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiaWF0IjoxNDM5OTIxMTUwLCJleHAiOjE0Mzk5MzE5NTB9.405vilVbToWvvb7drBzibiFht3Sufd8mmHwMfG-qvYE\"\n}",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/UsersController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/address/:id",
    "title": "Get Address Information",
    "version": "0.1.0",
    "name": "GetAddress",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n \"user_id\": 1,\n \"country\": \"USA\",\n \"state\": \"NY\",\n \"city\": \"NYC\",\n \"current\": \"void\",\n \"status\": \"void\",\n \"host\": \"no\",\n \"createdAt\": \"2015-08-19T16:35:10.000Z\",\n \"updatedAt\": \"2015-08-19T16:35:10.000Z\"\n }",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/AddressController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/bodyType/:id",
    "title": "Get Body Type Information",
    "version": "0.1.0",
    "name": "GetBodyType",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/BodyTypeController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/cuisine/:id",
    "title": "Get Cuisine Information",
    "version": "0.1.0",
    "name": "GetCuisine",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/CuisineController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/drink/:id",
    "title": "Get Drink Information",
    "version": "0.1.0",
    "name": "GetDrink",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/DrinkController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/hiv/:id",
    "title": "Get HIV Information",
    "version": "0.1.0",
    "name": "GetHiv",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/HivController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/music/:id",
    "title": "Get Music Information",
    "version": "0.1.0",
    "name": "GetMusic",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/MusicController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/occupation/:id",
    "title": "Get Occupation Information",
    "version": "0.1.0",
    "name": "GetOccupation",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/OccupationController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/socialNetworks/:id",
    "title": "Get Social Networks Information",
    "version": "0.1.0",
    "name": "GetSocialNetworks",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/SocialNetworksController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/sport/:id",
    "title": "Get Sport Information",
    "version": "0.1.0",
    "name": "GetSport",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/SportController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/training/:id",
    "title": "Get Training Information",
    "version": "0.1.0",
    "name": "GetTraining",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/TrainingController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/travel/:id",
    "title": "Get Travel Information",
    "version": "0.1.0",
    "name": "GetTravel",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/TravelController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/user/getUserInfo/",
    "title": "Get All User Information",
    "name": "Login",
    "group": "User",
    "version": "0.1.0",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "user_id",
            "description": "<p>Users Unique ID.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "User",
            "description": "<p>Data.</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "   {\n    \"user\": {\n        \"user_id\": 1,\n        \"email\": \"test@test.com\",\n        \"first_name\": null,\n        \"middle_name\": null,\n        \"last_name\": null,\n        \"birthday\": null,\n        \"phone\": null,\n        \"weight\": null,\n        \"height\": null,\n        \"relationship\": null,\n        \"sex\": null,\n        \"safeSex\": null,\n        \"areYouOut\": null,\n        \"endownment\": null,\n        \"sizeMatter\": null,\n        \"circumcisionPref\": null,\n        \"circumcision\": null,\n        \"hairStyle\": null,\n        \"hairColor\": null,\n        \"facialHair\": null,\n        \"tattoos\": null,\n        \"piercing\": null,\n        \"smoke\": null,\n        \"mood\": null,\n        \"aboutMyself\": null,\n        \"aboutDescription\": null,\n        \"bodyHair\": null,\n        \"ethnicity\": null,\n        \"sexInterest\": null,\n        \"lookingFor\": null,\n        \"role\": null,\n        \"fetish\": null,\n        \"fun\": null,\n        \"sexualIdentification\": null,\n        \"isLogged\": null,\n        \"createdAt\": \"2015-08-18T00:40:19.000Z\",\n        \"updatedAt\": \"2015-08-18T00:40:19.000Z\"\n     },\n    \"address\": {\n        \"user_id\": 1,\n        \"country\": \"usa\",\n        \"state\": \"NY\",\n        \"city\": \"NYC\",\n        \"current\": \"void\",\n        \"status\": \"void\",\n        \"host\": \"no\",\n        \"createdAt\": \"2015-08-19T16:35:10.000Z\",\n        \"updatedAt\": \"2015-08-19T19:38:02.000Z\"\n    },\n    \"bodyType\": {},\n    \"cuisine\": {},\n    \"drink\": {},\n    \"hiv\": {},\n    \"music\": {},\n    \"occupation\": {},\n    \"socialNetworks\": {},\n    \"sport\": {},\n    \"training\": {},\n    \"travel\": {}\n}",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/UsersController.js",
    "groupTitle": "User"
  },
  {
    "type": "get",
    "url": "/user/login/",
    "title": "Login The User",
    "name": "Login",
    "group": "User",
    "version": "0.1.0",
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Email</p> ",
            "optional": false,
            "field": "email",
            "description": "<p>Users Email.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "password",
            "description": "<p>Users Password</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>String</p> ",
            "optional": false,
            "field": "User",
            "description": "<p>Data + Token.</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "  {\n\"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Mzk5MjE0OTAsImV4cCI6MTQzOTkzMjI5MH0.IjUNLzucv-JWfIM7pa0oWJLvIWUllJ59Sh9ozblFhsA\"\n  }",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/UsersController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/address/",
    "title": "Post Address Information",
    "version": "0.1.0",
    "name": "PostAddress",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "country",
            "description": "<p>Optional Country Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "state",
            "description": "<p>Optional State Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "city",
            "description": "<p>Optional City Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "current",
            "description": "<p>Optional Current Address of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "status",
            "description": "<p>Optional Current Address Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Boolean</p> ",
            "optional": true,
            "field": "host",
            "description": "<p>Optional Host Availability of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      },
      "examples": [
        {
          "title": "Success-Response:",
          "content": "HTTP/1.1 200 OK\n{\n \"user_id\": 1,\n \"country\": \"USA\",\n \"state\": \"NY\",\n \"city\": \"NYC\",\n \"current\": \"void\",\n \"status\": \"void\",\n \"host\": \"no\",\n \"createdAt\": \"2015-08-19T16:35:10.000Z\",\n \"updatedAt\": \"2015-08-19T16:35:10.000Z\"\n }",
          "type": "json"
        }
      ]
    },
    "filename": "api/controllers/AddressController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/bodyType/",
    "title": "Post BodyType Information",
    "version": "0.1.0",
    "name": "PostBodyType",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "bodyType",
            "description": "<p>Optional Body Type of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "bustSize",
            "description": "<p>Optional Bust Size of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "bustMeasure",
            "description": "<p>Optional Bust Measure of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "chestMeasure",
            "description": "<p>Optional Chest Measure of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "waistMeasure",
            "description": "<p>Optional Waist Measure Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "hipsMeasure",
            "description": "<p>Optional Hips Measure of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/BodyTypeController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/cuisine/",
    "title": "Post Cuisine Information",
    "version": "0.1.0",
    "name": "PostCuisine",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "type",
            "description": "<p>Optional Cuisine Type of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/CuisineController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/drink/",
    "title": "Post Drink Information",
    "version": "0.1.0",
    "name": "PostDrink",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "doYouDrink",
            "description": "<p>Optional Drink Info of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "drink",
            "description": "<p>Optional Drink Type Info of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/DrinkController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/hiv/",
    "title": "Post HIV Information",
    "version": "0.1.0",
    "name": "PostHiv",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "status",
            "description": "<p>Optional HIV Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Date</p> ",
            "optional": true,
            "field": "lastTested",
            "description": "<p>Optional Last Tested Info of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/HivController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/music/",
    "title": "Post Music Information",
    "version": "0.1.0",
    "name": "PostMusic",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "style",
            "description": "<p>Optional Music Style of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/MusicController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/occupation/",
    "title": "Post Occupation Information",
    "version": "0.1.0",
    "name": "PostOccupation",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "occupation",
            "description": "<p>Optional Occupation Status of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "occupationDescription",
            "description": "<p>Optional Occupation Description of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Binary</p> ",
            "optional": true,
            "field": "resume",
            "description": "<p>Optional Resume doc of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/OccupationController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/socialNetworks/",
    "title": "Post Social Networks Information",
    "version": "0.1.0",
    "name": "PostSocialNetworks",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "linkedin",
            "description": "<p>Optional LinkedIn Link of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "facebook",
            "description": "<p>Optional Facebook Link of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "instagram",
            "description": "<p>Optional Instagram Link of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "twitter",
            "description": "<p>Optional Twitter Link of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "tumblr",
            "description": "<p>Optional Tumblr Link of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/SocialNetworksController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/sport/",
    "title": "Post Sport Information",
    "version": "0.1.0",
    "name": "PostSport",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "sport",
            "description": "<p>Optional Sports of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/SportController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/training/",
    "title": "Post Training Information",
    "version": "0.1.0",
    "name": "PostTraining",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "name",
            "description": "<p>Optional Training Name of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "latitude",
            "description": "<p>Optional Training Latitude Location of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "longitude",
            "description": "<p>Optional Training Longitude Location of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "workout",
            "description": "<p>Optional Workout of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>String</p> ",
            "optional": true,
            "field": "routine",
            "description": "<p>Optional Routine of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/TrainingController.js",
    "groupTitle": "User"
  },
  {
    "type": "post",
    "url": "/travel/",
    "title": "Post Travel Information",
    "version": "0.1.0",
    "name": "PostTravel",
    "group": "User",
    "header": {
      "fields": {
        "Header": [
          {
            "group": "Header",
            "type": "String",
            "optional": false,
            "field": "token",
            "description": "<p>Users unique token for this session</p> "
          }
        ]
      },
      "examples": [
        {
          "title": "Header-Example:",
          "content": "{\n    \"Authorization\": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8\n}",
          "type": "json"
        }
      ]
    },
    "parameter": {
      "fields": {
        "Parameter": [
          {
            "group": "Parameter",
            "type": "<p>Number</p> ",
            "optional": false,
            "field": "id",
            "description": "<p>Users unique ID.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "travelType",
            "description": "<p>Optional Travel Type of the User.</p> "
          },
          {
            "group": "Parameter",
            "type": "<p>Array</p> ",
            "optional": true,
            "field": "travelStyle",
            "description": "<p>Optional Travel Style of the User.</p> "
          }
        ]
      }
    },
    "success": {
      "fields": {
        "Success 200": [
          {
            "group": "Success 200",
            "type": "<p>Json</p> ",
            "optional": false,
            "field": "Info.",
            "description": ""
          }
        ]
      }
    },
    "filename": "api/controllers/TravelController.js",
    "groupTitle": "User"
  }
] });