import nodemailer from 'nodemailer'

// const transporter = nodemailer.createTransport({
//   host: "localhost",
//   port: 1025,
//   secure: false, // Use `true` for port 465, `false` for all other ports
//   auth: {
//     user: "",
//     pass: "",
//   },
// });

const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'stephon.bayer2@ethereal.email',
        pass: '7hcztx9aMBt4B2Us2Z'
    }
});

transporter.sendMail({
    from: '"Sidharth Ramesh 👻" <learn@medblocks.com>', // sender address
    to: "participant-bootcamp@test.com", // list of receivers
    subject: "Hello from FHIR Bootcamp 🔥", // Subject line
    html: "Your Patient Camila Lopez is <b>completely fine</b>.<br/>Or <em>is she?</em>", // html body
}).then(info => console.log(info))