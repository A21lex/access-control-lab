Code for Access Control Lab for DTU Data Security course, Fall 2017. DTU Compute.

Written by Aleksandrs Levi, s162870

To test the program, launch the **ApplicationServer** class first, then **Client**.  

To test authentication and access control, simply input different values of Password and Login as the parameters in service.authenticate call in line 40 of **Client** class before launching it:String token = service.authenticate(HenryPw, HenryLg). It should only work with provided examples at the top of the class, as they are the only users present in the ”PublicUserFile”

RBAC folder contains files defining the roles and assignment of users to roles based on RBAC approach.

acl file contains users and their corresponding permissions based on ACL approach.

To switch between using RBAC and ACL, change the **useRBAC** variable in **PrinterServant.java** class (true for RBAC, false for ACL).
