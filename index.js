import fs from 'fs'
import jose from 'node-jose'
import { randomUUID } from 'crypto'
import axios from 'axios'
import hyperquest from 'hyperquest'
import ndjson from 'ndjson'
import nodemailer from 'nodemailer'
import schedule from 'node-schedule'

const clientId = '1e8ca5c7-408c-401c-a5bd-ef33c4aace6d'
const tokenEndPoint =
  'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token'
const fhirBaseUrl = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4'
const group_id = 'e3iabhmS8rsueyz7vaimuiaSmfGvi.QwjVXJANlPOgR83'

// Generate a JWT with iat and exp
const createJWT = async payload => {
  const ks = fs.readFileSync('keys.json')
  const keyStore = await jose.JWK.asKeyStore(ks.toString())
  const key = keyStore.get({ use: 'sig' })
  return jose.JWS.createSign({ compact: true, fields: { typ: 'jwt' } }, key)
    .update(JSON.stringify(payload))
    .final()
}

const makeTokenRequest = async () => {
  const now = Math.floor(Date.now() / 1000)
  const jwt = await createJWT({
    iss: clientId,
    sub: clientId,
    aud: tokenEndPoint,
    jti: randomUUID(),
    iat: now,
    exp: now + 240
  })

  const formParams = new URLSearchParams()
  formParams.set('grant_type', 'client_credentials')
  formParams.set(
    'client_assertion_type',
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  )
  formParams.set('client_assertion', jwt)

  const tokenResponse = await axios.post(tokenEndPoint, formParams, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  })

  // console.log('tokenResponse: ', tokenResponse)

  return tokenResponse.data
}

const kickOffBulkDataExport = async accessToken => {
  const bulkKickoffResponse = await axios.get(
    `${fhirBaseUrl}/Group/${group_id}/$export`,
    {
      params: {
        _type: 'patient,observation',
        _typeFilter: 'Observation?category=laboratory'
      },
      headers: {
        Accept: 'application/fhir+json',
        Authorization: `Bearer ${accessToken}`,
        Prefer: 'respond-async'
      }
    }
  )

  return bulkKickoffResponse.headers.get('content-location')
}

const pollAndWaitForExport = async (url, accessToken, secsToWait = 10) => {
  try {
    const response = await axios.get(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    })

    const progress = response.headers['x-progress']
    const status = response.status
    const data = response.data

    // console.log({ url, status, progress, data })

    if (response.status === 200) {
      return response.data
    }
  } catch (e) {
    console.error('Error trying to get Bulk Request', e)
  }

  console.log(`Waiting ${secsToWait} secs`)
  await new Promise(resolve => setTimeout(resolve, secsToWait * 1000))
  return await pollAndWaitForExport(url, accessToken, secsToWait)
}

const processBulkResponse = async (bundleResponse, accessToken, type, fn) => {
  const filteredOutputs = bundleResponse.output.filter(
    output => output.type.toLowerCase() === type.toLowerCase()
  )

  const promises = filteredOutputs.map(output => {
    const url = output.url

    return new Promise(resolve => {
      const stream = hyperquest(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      })

      stream
        .pipe(ndjson.parse())
        .on('data', fn)
        .on('error', resolve) // Resolve on error to continue others
        .on('end', resolve) // Resolve when stream ends
    })
  })

  return await Promise.all(promises)
}

const checkIfObservationIsNormal = resource => {
  const value = resource?.valueQuantity?.value
  if (!resource?.referenceRange) {
    return { isNormal: false, reason: 'No reference range found' }
  }

  const referenceRangeLow = resource.referenceRange?.[0]?.low?.value
  const referenceRangeHigh = resource.referenceRange?.[0]?.high?.value

  if (!value || referenceRangeLow == null || referenceRangeHigh == null) {
    return { isNormal: false, reason: 'Incomplete data' }
  }

  if (value >= referenceRangeLow && value <= referenceRangeHigh) {
    return { isNormal: true, reason: 'Within reference range' }
  } else {
    return { isNormal: false, reason: 'Outside reference range' }
  }
}

const sendEmail = async body => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
      user: 'stephon.bayer2@ethereal.email',
      pass: '7hcztx9aMBt4B2Us2Z'
    }
  })
  return await transporter.sendMail(body)
}

const main = async () => {
  try {
    console.log('Runnung Main!!!!')
    const tokenResponse = await makeTokenRequest()
    const accessToken = tokenResponse.access_token
    const contentLocation = await kickOffBulkDataExport(accessToken)
    const bulkDataResponse = await pollAndWaitForExport(
      contentLocation,
      accessToken
    )
    // console.log(bulkDataResponse)

    const patients = {}

    await processBulkResponse(
      bulkDataResponse,
      accessToken,
      'Patient',
      resource => {
        patients[`Patient/${resource.id}`] =
          resource.name?.[0]?.text || 'Unknown'
      }
    )

    let abnormalObservations = ''
    let normalObservations = ''

    await processBulkResponse(
      bulkDataResponse,
      accessToken,
      'Observation',
      resource => {
        const { isNormal, reason } = checkIfObservationIsNormal(resource)
        const patientRef = resource.subject?.reference
        const patientName = patients[patientRef] || 'Unknown'

        const label = `${resource.code?.text || 'Unnamed test'}: ${
          resource.valueQuantity?.value ?? 'N/A'
        } Reason: ${reason}, Patient Name: ${patientName}\n`

        if (isNormal) {
          normalObservations += label
        } else {
          abnormalObservations += label
        }
      }
    )

    const message =
      `Results of lab tests in sandbox (Date: ${new Date().toISOString()})\n\n` +
      `Abnormal Observations:\n${abnormalObservations}\n` +
      `Normal Observations:\n${normalObservations}`

    console.log(message)

    const emailAck = await sendEmail({
      from: '"Siddhartha K S', // sender address
      to: 'participant-bootcamp@test.com', // list of receivers
      subject: `Lab report on ${new Date().toDateString()}`, // Subject line
      text: message,
      html: message.replace(/\n/g, '<br>')
    })
    console.log('emailAck: ', emailAck)
  } catch (err) {
    console.error('Error in main()', err)
  }
}
// schedule.scheduleJob('*/2 * * * *', main)

schedule.scheduleJob('0 9 * * *', main)
